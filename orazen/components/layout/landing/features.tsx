const Features = () => {
  return (
    <div className="flex flex-col lg:flex-row lg:divide-x  border-dashed">
      <div className="flex flex-col border-b  border-dashed">
        <div className="py-6 px-4 lg:px-6 flex flex-col gap-4">
          <p className="text-muted-foreground font-normal text-xs uppercase font-mono leading-4">
            Problem Statement
          </p>
          <div className="flex flex-col gap-2">
            <h2 className="text-foreground font-normal text-2xl flex flex-col cooper">
              <span className="text-foreground/70 font-normal">
                Digital inclusion fails when
              </span>
              <span className="italic">AI interactions are unsafe.</span>
            </h2>
            <p className="text-muted-foreground font-normal text-sm text-justify leading-5 ">
              Harmful responses, leaked data, and prompt abuse create trust
              barriers that block people from accessing information, services,
              and essential digital interactions.
            </p>
          </div>
        </div>
        <a
          className="px-4 lg:px-6 py-3 group border-t flex justify-between items-center transition-all duration-300 bg-background hover:bg-accent/30 border-dashed"
          href="/transactional-emails"
        >
          <p className="text-foreground font-medium text-sm uppercase font-mono group-hover:text-primary">
            Barrier Focus
          </p>
          <span className="text-muted-foreground transition-all duration-100 group-hover:text-primary group-hover:translate-x-1 group-hover:scale-110 transform-gpu">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
            >
              <path
                d="M5 12H19.5833M19.5833 12L12.5833 5M19.5833 12L12.5833 19"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                vectorEffect="non-scaling-stroke"
              ></path>
            </svg>
          </span>
        </a>
      </div>
      <div className="flex flex-col border-b  border-dashed">
        <div className="py-6 px-4 lg:px-6 flex flex-col gap-4">
          <p className="text-muted-foreground font-normal text-xs uppercase font-mono leading-4">
            Orazen Solution
          </p>
          <div className="flex flex-col gap-2">
            <h2 className="text-foreground font-normal text-2xl flex flex-col cooper">
              <span className="text-foreground/70 font-normal">
                Self-hosted safety layer
              </span>
              <span className="italic">for equitable participation.</span>
            </h2>
            <p className="text-muted-foreground font-normal text-sm text-justify leading-5 ">
              Orazen combines real-time guardrails, red-team validation, and
              observability so AI-powered services stay safe, reliable, and
              usable for everyone.
            </p>
          </div>
        </div>
        <a
          className="px-4 lg:px-6 py-3 group border-t  flex justify-between items-center transition-all duration-300 bg-background hover:bg-accent/30 border-dashed"
          href="/marketing-emails"
        >
          <p className="text-foreground font-medium text-sm uppercase font-mono group-hover:text-primary">
            Inclusion Architecture
          </p>
          <span className="text-muted-foreground transition-all duration-100 group-hover:text-primary group-hover:translate-x-1 group-hover:scale-110 transform-gpu">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
            >
              <path
                d="M5 12H19.5833M19.5833 12L12.5833 5M19.5833 12L12.5833 19"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                vectorEffect="non-scaling-stroke"
              ></path>
            </svg>
          </span>
        </a>
      </div>
    </div>
  );
};

export default Features;
