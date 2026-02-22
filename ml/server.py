import asyncio
import threading
import time
import uuid
from concurrent import futures
from typing import Any, Dict, List, Optional

import grpc

import ml_service_pb2
import ml_service_pb2_grpc
import torch
from loguru import logger
from scanners.garak_scanner import GarakScanner

from scanners.llm_guard_scanner import LLMGuardScanner, _parse_settings

SCAN_RETENTION_SECONDS = 3600  # Keep completed scans for 1 hour
SCAN_CLEANUP_INTERVAL_SECONDS = 300  # Clean up every 5 minutes
SCAN_STALE_TIMEOUT_SECONDS = 1800  # Consider running scans stale after 30 minutes
MAX_RUNNING_SCANS = 10  # Maximum concurrent scans


class MlServiceServicer(ml_service_pb2_grpc.MlServiceServicer):
    def __init__(self):
        logger.info("Initializing ML Service (GPU-ONLY mode)...")
        if not torch.cuda.is_available():
            logger.critical(
                "FATAL: No NVIDIA GPU detected (torch.cuda.is_available() == False).\n"
                "This sidecar is GPU-ONLY and will NOT run on CPU.\n"
                "Requirements:\n"
                "  • NVIDIA GPU with CUDA support\n"
                "  • NVIDIA driver installed on the host\n"
                "  • NVIDIA Container Toolkit installed (for Docker)\n"
                "  • Container started with --gpus all (or deploy.resources.reservations in compose)\n"
                "Verify with: docker run --rm --gpus all nvidia/cuda:12.1.1-base-ubuntu22.04 nvidia-smi"
            )
            raise SystemExit(1)

        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        logger.info(f"NVIDIA GPU detected: {gpu_name} ({gpu_mem:.1f} GB)")

        device = "cuda"
        logger.info(f"Using device: {device}")
        try:
            self.llm_guard = LLMGuardScanner(device=device)
        except Exception as e:
            logger.critical(
                f"FATAL: LLM Guard failed to initialize on GPU: {e}\n"
                "The sidecar CANNOT start without real LLM Guard ML models on CUDA.\n"
                "Make sure 'llm-guard' and its dependencies (torch+cuda, transformers) "
                "are installed correctly.\n"
                "Run: pip install llm-guard torch transformers"
            )
            raise SystemExit(1) from e

        self.garak = GarakScanner()
        self.running_scans: Dict[str, dict] = {}
        self._scans_lock = threading.Lock()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

        logger.info(
            "ML Service initialized successfully — GPU-ONLY with REAL LLM Guard ML models"
        )

    def _cleanup_loop(self):
        """Background thread to clean up old scans"""
        while True:
            time.sleep(SCAN_CLEANUP_INTERVAL_SECONDS)
            self._cleanup_old_scans()

    def _cleanup_old_scans(self):
        """Remove old scans and mark stale running scans as failed"""
        now = time.time()
        scans_to_remove = []
        stale_scans = []

        with self._scans_lock:
            for scan_id, scan_data in self.running_scans.items():
                status = scan_data["status"]
                created_at = scan_data.get("created_at", 0)
                completed_at = scan_data.get("completed_at")

                if status in ("completed", "failed", "cancelled"):
                    if completed_at and now - completed_at > SCAN_RETENTION_SECONDS:
                        scans_to_remove.append(scan_id)

                elif status in ("running", "queued"):
                    if now - created_at > SCAN_STALE_TIMEOUT_SECONDS:
                        stale_scans.append(scan_id)

            for scan_id in stale_scans:
                self.running_scans[scan_id].update(
                    {
                        "status": "failed",
                        "error_message": "Scan timed out (stale)",
                        "completed_at": now,
                    }
                )
                logger.warning(f"Marked stale scan as failed: {scan_id}")

            for scan_id in scans_to_remove:
                del self.running_scans[scan_id]
                logger.debug(f"Cleaned up old scan: {scan_id}")

        if stale_scans:
            logger.info(f"Marked {len(stale_scans)} stale scan(s) as failed")
        if scans_to_remove:
            logger.info(f"Cleaned up {len(scans_to_remove)} old scan(s)")

    def _get_active_scan_count(self) -> int:
        """Count scans that are queued or running"""
        with self._scans_lock:
            return sum(
                1
                for s in self.running_scans.values()
                if s["status"] in ("queued", "running")
            )

    def HealthCheck(self, request, context):
        """Health check endpoint — confirms real LLM Guard is loaded"""
        return ml_service_pb2.HealthResponse(
            healthy=True,
            version="0.2.0-llmguard-advanced",
            available_input_scanners=LLMGuardScanner.get_available_input_scanners(),
            available_output_scanners=LLMGuardScanner.get_available_output_scanners(),
        )

    def ScanPrompt(self, request, context):
        """Scan a prompt using LLM Guard"""
        start_time = time.time()

        if not request.prompt:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Prompt cannot be empty")
            return ml_service_pb2.ScanResponse()

        if len(request.prompt) > 32 * 1024:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Prompt exceeds maximum length of 32KB")
            return ml_service_pb2.ScanResponse()

        try:
            result = self.llm_guard.scan_prompt(
                prompt=request.prompt,
                check_injection=request.check_injection,
                check_toxicity=request.check_toxicity,
                check_pii=request.check_pii,
                sanitize=request.sanitize,
            )

            latency_ms = int((time.time() - start_time) * 1000)

            threats = [
                ml_service_pb2.Threat(
                    threat_type=t["type"],
                    confidence=t["confidence"],
                    description=t["description"],
                    severity=t["severity"],
                )
                for t in result.get("threats", [])
            ]

            return ml_service_pb2.ScanResponse(
                safe=result["safe"],
                sanitized_prompt=result.get("sanitized_prompt", ""),
                risk_score=result.get("risk_score", 0.0),
                threats=threats,
                latency_ms=latency_ms,
            )

        except Exception as e:
            logger.error(f"Error scanning prompt: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Scan failed: {str(e)}")
            return ml_service_pb2.ScanResponse()

    def ScanOutput(self, request, context):
        """Scan LLM output using LLM Guard"""
        start_time = time.time()

        if not request.output:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Output cannot be empty")
            return ml_service_pb2.OutputScanResponse()

        try:
            result = self.llm_guard.scan_output(
                output=request.output, original_prompt=request.original_prompt or None
            )

            latency_ms = int((time.time() - start_time) * 1000)

            issues = [
                ml_service_pb2.OutputIssue(
                    issue_type=i["type"],
                    description=i["description"],
                    severity=i["severity"],
                )
                for i in result.get("issues", [])
            ]

            return ml_service_pb2.OutputScanResponse(
                safe=result["safe"],
                sanitized_output=result.get("sanitized_output", ""),
                issues=issues,
                latency_ms=latency_ms,
            )

        except Exception as e:
            logger.error(f"Error scanning output: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Output scan failed: {str(e)}")
            return ml_service_pb2.OutputScanResponse()

    def AdvancedScan(self, request, context):
        start_time = time.time()

        scan_mode = request.scan_mode

        if scan_mode in (0, 2) and not request.prompt:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Prompt is required for PROMPT_ONLY or BOTH scan modes")
            return ml_service_pb2.AdvancedScanResponse()

        if scan_mode in (1, 2) and not request.output:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Output is required for OUTPUT_ONLY or BOTH scan modes")
            return ml_service_pb2.AdvancedScanResponse()

        if request.prompt and len(request.prompt) > 64 * 1024:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Prompt exceeds maximum length of 64KB")
            return ml_service_pb2.AdvancedScanResponse()

        if request.output and len(request.output) > 64 * 1024:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Output exceeds maximum length of 64KB")
            return ml_service_pb2.AdvancedScanResponse()

        try:
            # Convert proto scanner configs to dicts
            input_scanner_configs = None
            if request.input_scanners:
                input_scanner_configs = {}
                for name, cfg in request.input_scanners.items():
                    input_scanner_configs[name] = {
                        "enabled": cfg.enabled,
                        "threshold": cfg.threshold if cfg.threshold > 0 else 0.5,
                        "settings": _parse_settings(cfg.settings_json),
                    }

            output_scanner_configs = None
            if request.output_scanners:
                output_scanner_configs = {}
                for name, cfg in request.output_scanners.items():
                    output_scanner_configs[name] = {
                        "enabled": cfg.enabled,
                        "threshold": cfg.threshold if cfg.threshold > 0 else 0.5,
                        "settings": _parse_settings(cfg.settings_json),
                    }

            # Execute advanced scan
            result = self.llm_guard.advanced_scan(
                prompt=request.prompt,
                output=request.output,
                scan_mode=scan_mode,
                input_scanner_configs=input_scanner_configs,
                output_scanner_configs=output_scanner_configs,
                sanitize=request.sanitize,
                fail_fast=request.fail_fast,
            )

            latency_ms = int((time.time() - start_time) * 1000)

            # Build proto input results
            input_results = [
                ml_service_pb2.ScannerResult(
                    scanner_name=r["scanner_name"],
                    is_valid=r["is_valid"],
                    score=r["score"],
                    description=r.get("description", ""),
                    severity=r.get("severity", "low"),
                    scanner_latency_ms=r.get("scanner_latency_ms", 0),
                )
                for r in result.get("input_results", [])
            ]

            # Build proto output results
            output_results = [
                ml_service_pb2.ScannerResult(
                    scanner_name=r["scanner_name"],
                    is_valid=r["is_valid"],
                    score=r["score"],
                    description=r.get("description", ""),
                    severity=r.get("severity", "low"),
                    scanner_latency_ms=r.get("scanner_latency_ms", 0),
                )
                for r in result.get("output_results", [])
            ]

            return ml_service_pb2.AdvancedScanResponse(
                safe=result["safe"],
                sanitized_prompt=result.get("sanitized_prompt", ""),
                sanitized_output=result.get("sanitized_output", ""),
                risk_score=result.get("risk_score", 0.0),
                input_results=input_results,
                output_results=output_results,
                latency_ms=latency_ms,
                scan_mode=scan_mode,
                input_scanners_run=result.get("input_scanners_run", 0),
                output_scanners_run=result.get("output_scanners_run", 0),
            )

        except Exception as e:
            logger.error(f"Error in AdvancedScan: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Advanced scan failed: {str(e)}")
            return ml_service_pb2.AdvancedScanResponse()

    def StartGarakScan(self, request, context):
        """Start a Garak vulnerability scan"""
        # Validate required fields
        if not request.provider:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Provider is required")
            return ml_service_pb2.GarakResponse()

        if not request.model:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Model is required")
            return ml_service_pb2.GarakResponse()

        # Check Garak availability
        if not self.garak.is_available():
            context.set_code(grpc.StatusCode.UNAVAILABLE)
            context.set_details(
                "Garak scanner is not available. Please install garak package."
            )
            return ml_service_pb2.GarakResponse()

        # Check concurrent scan limit
        if self._get_active_scan_count() >= MAX_RUNNING_SCANS:
            context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
            context.set_details(
                f"Maximum concurrent scans ({MAX_RUNNING_SCANS}) reached. "
                "Please wait for existing scans to complete."
            )
            return ml_service_pb2.GarakResponse()

        # Extract custom endpoint config if provided
        custom_endpoint = None
        if request.HasField("custom_endpoint") and request.custom_endpoint.url:
            custom_endpoint = {
                "url": request.custom_endpoint.url,
                "method": request.custom_endpoint.method or "POST",
                "request_template": request.custom_endpoint.request_template
                or '{"prompt": "{{prompt}}"}',
                "response_path": request.custom_endpoint.response_path or "response",
                "headers": dict(request.custom_endpoint.headers)
                if request.custom_endpoint.headers
                else {},
            }
            logger.info(f"Custom endpoint configured: {custom_endpoint['url']}")

        max_prompts = (
            request.max_prompts_per_probe if request.max_prompts_per_probe > 0 else 0
        )

        try:
            scan_id = str(uuid.uuid4())

            with self._scans_lock:
                self.running_scans[scan_id] = {
                    "status": "queued",
                    "progress": 0,
                    "probes_completed": 0,
                    "probes_total": 0,
                    "vulnerabilities": [],
                    "probe_logs": [],
                    "created_at": time.time(),
                    "completed_at": None,
                    "provider": request.provider,
                    "model": request.model,
                    "custom_endpoint": custom_endpoint,
                }

            def run_scan_in_thread():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(
                        self._run_garak_scan(
                            scan_id=scan_id,
                            provider=request.provider,
                            model=request.model,
                            api_key=request.api_key,
                            base_url=request.base_url,
                            probes=list(request.probes),
                            scan_type=request.scan_type,
                            custom_endpoint=custom_endpoint,
                            max_prompts_per_probe=max_prompts
                            if max_prompts > 0
                            else None,
                        )
                    )
                finally:
                    loop.close()

            thread = threading.Thread(target=run_scan_in_thread, daemon=True)
            thread.start()

            return ml_service_pb2.GarakResponse(
                scan_id=scan_id, status="queued", estimated_duration_seconds=300
            )

        except Exception as e:
            logger.error(f"Error starting Garak scan: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Failed to start scan: {str(e)}")
            return ml_service_pb2.GarakResponse()

    def _vuln_dict_to_proto(self, v: Dict[str, Any]) -> ml_service_pb2.Vulnerability:
        """Convert a vulnerability dict to a protobuf Vulnerability message."""
        return ml_service_pb2.Vulnerability(
            probe_name=v.get("probe_name", ""),
            category=v.get("category", ""),
            severity=v.get("severity", ""),
            description=v.get("description", ""),
            attack_prompt=v.get("attack_prompt", ""),
            model_response=v.get("model_response", ""),
            recommendation=v.get("recommendation", ""),
            success_rate=v.get("success_rate", 0.0),
            detector_name=v.get("detector_name", ""),
            probe_class=v.get("probe_class", ""),
            probe_duration_ms=v.get("probe_duration_ms", 0),
        )

    def _probe_log_dict_to_proto(self, pl: Dict[str, Any]) -> ml_service_pb2.ProbeLog:
        """Convert a probe log dict to a protobuf ProbeLog message."""
        return ml_service_pb2.ProbeLog(
            probe_name=pl.get("probe_name", ""),
            probe_class=pl.get("probe_class", ""),
            status=pl.get("status", ""),
            started_at_ms=pl.get("started_at_ms", 0),
            completed_at_ms=pl.get("completed_at_ms", 0),
            duration_ms=pl.get("duration_ms", 0),
            prompts_sent=pl.get("prompts_sent", 0),
            prompts_passed=pl.get("prompts_passed", 0),
            prompts_failed=pl.get("prompts_failed", 0),
            detector_name=pl.get("detector_name", ""),
            detector_scores=pl.get("detector_scores", []),
            error_message=pl.get("error_message", ""),
            log_lines=pl.get("log_lines", []),
        )

    def GetGarakStatus(self, request, context):
        """Get status of a running Garak scan — includes intermediate vulns and probe logs"""
        scan_id = request.scan_id

        if not scan_id:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Scan ID is required")
            return ml_service_pb2.GarakStatusResponse()

        with self._scans_lock:
            if scan_id not in self.running_scans:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f"Scan {scan_id} not found")
                return ml_service_pb2.GarakStatusResponse()

            scan = self.running_scans[scan_id]

            vulnerabilities = [
                self._vuln_dict_to_proto(v) for v in scan.get("vulnerabilities", [])
            ]

            probe_logs = [
                self._probe_log_dict_to_proto(pl) for pl in scan.get("probe_logs", [])
            ]

            return ml_service_pb2.GarakStatusResponse(
                scan_id=scan_id,
                status=scan["status"],
                progress=scan["progress"],
                probes_completed=scan["probes_completed"],
                probes_total=scan["probes_total"],
                vulnerabilities_found=len(vulnerabilities),
                vulnerabilities=vulnerabilities,
                error_message=scan.get("error_message", ""),
                probe_logs=probe_logs,
            )

    def CancelGarakScan(self, request, context):
        """Cancel a running Garak scan"""
        scan_id = request.scan_id

        if not scan_id:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Scan ID is required")
            return ml_service_pb2.GarakResponse()

        with self._scans_lock:
            if scan_id not in self.running_scans:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f"Scan {scan_id} not found")
                return ml_service_pb2.GarakResponse()

            scan = self.running_scans[scan_id]

            if scan["status"] in ("completed", "failed", "cancelled"):
                return ml_service_pb2.GarakResponse(
                    scan_id=scan_id,
                    status=scan["status"],
                )

            scan["status"] = "cancelled"
            scan["completed_at"] = time.time()

            return ml_service_pb2.GarakResponse(
                scan_id=scan_id,
                status="cancelled",
            )

    def ListGarakProbes(self, request, context):
        """List all available Garak probes with metadata for the probe picker UI"""
        try:
            probe_data = self.garak.get_available_probes()

            categories = []
            for cat_id, cat_info in probe_data.get("categories", {}).items():
                categories.append(
                    ml_service_pb2.GarakProbeCategory(
                        id=cat_id,
                        name=cat_info.get("name", cat_id),
                        description=cat_info.get("description", ""),
                        icon=cat_info.get("icon", ""),
                        probe_ids=cat_info.get("probe_ids", []),
                    )
                )

            probes = []
            for probe_id, probe_info in probe_data.get("probes", {}).items():
                probes.append(
                    ml_service_pb2.GarakProbeInfo(
                        id=probe_id,
                        name=probe_info.get("name", probe_id),
                        description=probe_info.get("description", ""),
                        category=probe_info.get("category", "other"),
                        severity_range=probe_info.get("severity_range", "medium"),
                        default_enabled=probe_info.get("default_enabled", False),
                        tags=probe_info.get("tags", []),
                        class_paths=probe_info.get("class_paths", []),
                        available=probe_info.get("available", False),
                    )
                )

            return ml_service_pb2.GarakProbeListResponse(
                categories=categories,
                probes=probes,
            )

        except Exception as e:
            logger.error(f"ListGarakProbes failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Failed to list probes: {str(e)}")
            return ml_service_pb2.GarakProbeListResponse()

    def RetestProbe(self, request, context):
        """Retest a specific vulnerability by re-running the same probe/prompt multiple times"""
        if not request.provider or not request.model:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Provider and model are required for retest")
            return ml_service_pb2.RetestResponse()

        if not request.attack_prompt:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Attack prompt is required for retest")
            return ml_service_pb2.RetestResponse()

        if not self.garak.is_available():
            context.set_code(grpc.StatusCode.UNAVAILABLE)
            context.set_details("Garak scanner is not available")
            return ml_service_pb2.RetestResponse()

        num_attempts = request.num_attempts if request.num_attempts > 0 else 3

        try:
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(
                    self.garak.retest_probe(
                        probe_name=request.probe_name,
                        probe_class=request.probe_class,
                        attack_prompt=request.attack_prompt,
                        provider=request.provider,
                        model=request.model,
                        api_key=request.api_key,
                        base_url=request.base_url,
                        num_attempts=num_attempts,
                    )
                )
            finally:
                loop.close()

            retest_results = [
                ml_service_pb2.RetestResult(
                    attempt_number=r.get("attempt_number", 0),
                    is_vulnerable=r.get("is_vulnerable", False),
                    model_response=r.get("model_response", ""),
                    detector_score=r.get("detector_score", 0.0),
                    duration_ms=r.get("duration_ms", 0),
                    error_message=r.get("error_message", ""),
                )
                for r in result.get("results", [])
            ]

            return ml_service_pb2.RetestResponse(
                probe_name=result.get("probe_name", request.probe_name),
                attack_prompt=result.get("attack_prompt", request.attack_prompt),
                total_attempts=result.get("total_attempts", num_attempts),
                vulnerable_count=result.get("vulnerable_count", 0),
                safe_count=result.get("safe_count", 0),
                confirmation_rate=result.get("confirmation_rate", 0.0),
                results=retest_results,
                status=result.get("status", "completed"),
                error_message=result.get("error_message", ""),
            )

        except Exception as e:
            logger.error(f"Retest failed: {e}")
            return ml_service_pb2.RetestResponse(
                probe_name=request.probe_name,
                attack_prompt=request.attack_prompt,
                total_attempts=0,
                status="error",
                error_message=str(e),
            )

    def GetScanLogs(self, request, context):
        """Get detailed per-probe execution logs for a scan"""
        scan_id = request.scan_id

        if not scan_id:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Scan ID is required")
            return ml_service_pb2.ScanLogsResponse()

        with self._scans_lock:
            if scan_id not in self.running_scans:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f"Scan {scan_id} not found")
                return ml_service_pb2.ScanLogsResponse()

            scan = self.running_scans[scan_id]

            probe_logs = [
                self._probe_log_dict_to_proto(pl) for pl in scan.get("probe_logs", [])
            ]

            total_prompts = sum(
                pl.get("prompts_sent", 0) for pl in scan.get("probe_logs", [])
            )
            total_duration = sum(
                pl.get("duration_ms", 0) for pl in scan.get("probe_logs", [])
            )

            return ml_service_pb2.ScanLogsResponse(
                scan_id=scan_id,
                logs=probe_logs,
                total_probes=scan.get("probes_total", 0),
                total_prompts_sent=total_prompts,
                total_duration_ms=total_duration,
            )

    async def _run_garak_scan(
        self,
        scan_id: str,
        provider: str,
        model: str,
        api_key: str,
        base_url: str,
        probes: List[str],
        scan_type: str,
        custom_endpoint: Optional[Dict[str, Any]] = None,
        max_prompts_per_probe: Optional[int] = None,
    ):
        """Run Garak scan in background with streaming callbacks"""
        try:
            with self._scans_lock:
                if scan_id in self.running_scans:
                    # Check if cancelled before starting
                    if self.running_scans[scan_id]["status"] == "cancelled":
                        return
                    self.running_scans[scan_id]["status"] = "running"

            def on_vulnerability_found(vuln: Dict[str, Any]):
                """Called immediately when a vulnerability is discovered during scanning."""
                with self._scans_lock:
                    if scan_id in self.running_scans:
                        self.running_scans[scan_id]["vulnerabilities"].append(vuln)
                        logger.info(
                            f"[{scan_id[:8]}] Streaming vuln: "
                            f"{vuln.get('probe_name')} / {vuln.get('severity')}"
                        )

            def on_probe_log(probe_log: Dict[str, Any]):
                """Called when a probe finishes execution (pass or fail)."""
                with self._scans_lock:
                    if scan_id in self.running_scans:
                        self.running_scans[scan_id]["probe_logs"].append(probe_log)
                        logger.debug(
                            f"[{scan_id[:8]}] Probe log: "
                            f"{probe_log.get('probe_name')} → {probe_log.get('status')} "
                            f"({probe_log.get('duration_ms', 0)}ms)"
                        )

            result = await self.garak.run_scan(
                provider=provider,
                model=model,
                api_key=api_key,
                base_url=base_url,
                probes=probes,
                scan_type=scan_type,
                custom_endpoint=custom_endpoint,
                max_prompts_per_probe=max_prompts_per_probe,
                progress_callback=lambda p, c, t: self._update_scan_progress(
                    scan_id, p, c, t
                ),
                vulnerability_callback=on_vulnerability_found,
                log_callback=on_probe_log,
                cancel_check=lambda: self._is_scan_cancelled(scan_id),
            )

            with self._scans_lock:
                if scan_id in self.running_scans:
                    if self.running_scans[scan_id]["status"] != "cancelled":
                        existing_vulns = self.running_scans[scan_id]["vulnerabilities"]
                        final_vulns = result.get("vulnerabilities", [])
                        if len(final_vulns) > len(existing_vulns):
                            self.running_scans[scan_id]["vulnerabilities"] = final_vulns

                        existing_logs = self.running_scans[scan_id]["probe_logs"]
                        final_logs = result.get("probe_logs", [])
                        if len(final_logs) > len(existing_logs):
                            self.running_scans[scan_id]["probe_logs"] = final_logs

                        result_status = result.get("status", "completed")
                        if result_status == "failed":
                            error_msg = result.get(
                                "error",
                                "Scan failed — check probe logs for details",
                            )
                            logger.error(f"Scan {scan_id} failed: {error_msg}")
                            self.running_scans[scan_id].update(
                                {
                                    "status": "failed",
                                    "error_message": error_msg,
                                    "completed_at": time.time(),
                                }
                            )
                        else:
                            self.running_scans[scan_id].update(
                                {
                                    "status": "completed",
                                    "progress": 100,
                                    "completed_at": time.time(),
                                }
                            )

        except Exception as e:
            logger.error(f"Garak scan {scan_id} failed: {e}")
            with self._scans_lock:
                if scan_id in self.running_scans:
                    self.running_scans[scan_id].update(
                        {
                            "status": "failed",
                            "error_message": str(e),
                            "completed_at": time.time(),
                        }
                    )

    def _is_scan_cancelled(self, scan_id: str) -> bool:
        """Check if a scan has been cancelled"""
        with self._scans_lock:
            if scan_id in self.running_scans:
                return self.running_scans[scan_id]["status"] == "cancelled"
        return True

    def _update_scan_progress(
        self, scan_id: str, progress: int, completed: int, total: int
    ):
        """Update scan progress"""
        with self._scans_lock:
            if scan_id in self.running_scans:
                self.running_scans[scan_id].update(
                    {
                        "progress": progress,
                        "probes_completed": completed,
                        "probes_total": total,
                    }
                )

def serve():
    """Start the gRPC server"""
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=[
            ("grpc.max_send_message_length", 50 * 1024 * 1024),
            ("grpc.max_receive_message_length", 50 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 30000),
            ("grpc.keepalive_timeout_ms", 10000),
            ("grpc.keepalive_permit_without_calls", 1),
        ],
    )

    ml_service_pb2_grpc.add_MlServiceServicer_to_server(MlServiceServicer(), server)

    port = 50051
    server.add_insecure_port(f"[::]:{port}")
    server.start()

    logger.info(f"ML Sidecar gRPC server started on port {port}")

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        server.stop(grace=5)

if __name__ == "__main__":
    serve()
