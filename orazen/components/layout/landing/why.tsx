const startupPillars = [
  {
    title: "Safe Access to Information",
    weight: "Theme",
    description:
      "Guardrails reduce harmful responses so users can trust AI-generated information in critical workflows.",
  },
  {
    title: "Inclusive Digital Interactions",
    weight: "Theme",
    description:
      "Prompt and output validation helps keep interactions respectful, reliable, and usable for diverse audiences.",
  },
  {
    title: "Equitable Service Delivery",
    weight: "Impact",
    description:
      "By reducing abuse and instability, AI services remain available to more people across education, public service, and support platforms.",
  },
  {
    title: "Operational Feasibility",
    weight: "Execution",
    description:
      "One docker-compose deployment with observability, keys, quotas, and auth enables practical real-world rollout.",
  },
  {
    title: "Scalable Performance",
    weight: "Execution",
    description:
      "GPU-accelerated scanning and caching keep latency low as usage grows across teams and endpoints.",
  },
  {
    title: "Adaptable Team Workflow",
    weight: "Collaboration",
    description:
      "Unified dashboard, logs, and API controls help teams iterate quickly and coordinate effectively under pressure.",
  },
];

const Why = () => {
  return (
    <section id="technical" className="mt-30 flex flex-col items-center gap-6">
      <div className="flex flex-col items-center gap-4 px-4 lg:px-6">
        <p className="text-stone-800 font-normal text-xs uppercase font-mono leading-4">
          Theme Alignment
        </p>
        <p className="cooper text-center text-2xl font-normal text-stone-800 lg:whitespace-pre-line">
          Orazen uses AI security to enable digital inclusion and accessibility.
          <br />
          The goal is safer access, not security for security&apos;s sake.
        </p>
      </div>

      <ul className="grid w-full grid-cols-1 border-y border-dashed divide-y divide-dashed md:grid-cols-2 md:divide-x lg:grid-cols-3">
        {startupPillars.map((item) => (
          <li key={item.title} className="flex flex-col gap-3 px-4 py-6 lg:px-6">
            <p className="jetbrains-mono text-xs uppercase tracking-wide text-indigo-600">
              {item.weight}
            </p>
            <p className="font-mono text-sm font-semibold uppercase leading-5 text-stone-800">
              {item.title}
            </p>
            <p className="text-sm leading-5 text-stone-600 dark:text-stone-500">
              {item.description}
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
};

export default Why;
