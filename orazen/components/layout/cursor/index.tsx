"use client";
import React, { useRef, useEffect } from "react";

interface ClickSparkProps {
  activeOn?: string;
}

const ClickSpark: React.FC<ClickSparkProps> = ({ activeOn }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const rootRef = useRef<HTMLElement | null>(null);

  const setSparkPosition = (e: MouseEvent) => {
    if (!svgRef.current || !rootRef.current) return;

    const rect = rootRef.current.getBoundingClientRect();
    svgRef.current.style.left = `${e.clientX - rect.left - svgRef.current.clientWidth / 2}px`;
    svgRef.current.style.top = `${e.clientY - rect.top - svgRef.current.clientHeight / 2}px`;
  };

  const animateSpark = () => {
    if (!svgRef.current) return;

    const sparks = Array.from(svgRef.current.children) as SVGLineElement[];
    const size = parseInt(sparks[0].getAttribute("y1") || "0");
    const offset = `${size / 2}px`;

    const options = {
      duration: 660,
      easing: "cubic-bezier(0.25, 1, 0.5, 1)",
      fill: "forwards" as FillMode,
    };

    sparks.forEach((spark, i) => {
      const deg = `calc(${i} * (360deg / ${sparks.length}))`;
      const keyframes = [
        {
          strokeDashoffset: size * 3,
          transform: `rotate(${deg}) translateY(${offset})`,
        },
        {
          strokeDashoffset: size,
          transform: `rotate(${deg}) translateY(0)`,
        },
      ];
      spark.animate(keyframes, options);
    });
  };

  useEffect(() => {
    rootRef.current = document.documentElement;

    const handleClick = (e: MouseEvent) => {
      const target = e.target as Element | null;
      if (activeOn && target && !target.matches(activeOn)) return;
      setSparkPosition(e);
      animateSpark();
    };

    rootRef.current.addEventListener("click", handleClick);
    return () => {
      rootRef.current?.removeEventListener("click", handleClick);
    };
  }, [activeOn]);

  return (
    <div style={{ display: "contents" }}>
      <svg
        ref={svgRef}
        width="30"
        height="30"
        viewBox="0 0 100 100"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="4"
        style={{
          pointerEvents: "none",
          position: "absolute",
          zIndex: 999999999,
          rotate: "-20deg",
          stroke: "rgb(--foreground)",
        }}
        className="dark:stroke-white stroke-black"
      >
        {Array.from({ length: 8 }).map((_, index) => (
          <line
            key={index}
            x1="50"
            y1="30"
            x2="50"
            y2="4"
            style={{
              strokeDasharray: "30",
              strokeDashoffset: "30",
              transformOrigin: "center",
            }}
          />
        ))}
      </svg>
    </div>
  );
};

export default ClickSpark;
