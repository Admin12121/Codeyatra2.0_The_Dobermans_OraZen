const Demo = () => {
  return (
    <div className="flex flex-col w-full  gap-6 mt-30">
      <div className="flex flex-col gap-2 items-center px-4 lg:px-0">
        <p className="text-stone-800 font-normal text-xs uppercase font-mono leading-4 text-center">
          Impact Snapshot
        </p>
        <p className="text-stone-800 font-normal text-2xl cooper text-center">
          Real capabilities aligned to inclusive digital access
        </p>
      </div>
      <ul className="grid lg:grid-cols-3 border-y  grid-cols-1 divide-dashed divide-y lg:divide-y-0 lg:divide-x  border-dashed">
        <li className="flex flex-col gap-4 px-4 lg:px-6 py-6 bg-stone-0">
          <p className="text-lime-600 font-normal text-xl leading-6">50-100ms</p>
          <div className="flex flex-col gap-1">
            <p className="text-stone-800 font-semibold text-xs font-mono leading-4 uppercase">
              REAL-TIME PROTECTION
            </p>
            <p className="text-stone-800 font-normal text-sm leading-5 whitespace-pre-line">
              Fast guard response helps users complete AI-assisted tasks without
              delay while reducing harmful or misleading interactions.
            </p>
          </div>
        </li>
        <li className="flex flex-col gap-4 px-4 lg:px-6 py-6 bg-stone-0">
          <p className="text-lime-600 font-normal text-xl leading-6">150+ Probes</p>
          <div className="flex flex-col gap-1">
            <p className="text-stone-800 font-semibold text-xs font-mono leading-4 uppercase">
              COVERAGE DEPTH
            </p>
            <p className="text-stone-800 font-normal text-sm leading-5 whitespace-pre-line">
              15+ configurable guard scanners plus 150+ red-team probes validate
              reliability before unsafe behavior reaches end users.
            </p>
          </div>
        </li>
        <li className="flex flex-col gap-4 px-4 lg:px-6 py-6 bg-stone-0">
          <p className="text-lime-600 font-normal text-xl leading-6">Self-Hosted</p>
          <div className="flex flex-col gap-1">
            <p className="text-stone-800 font-semibold text-xs font-mono leading-4 uppercase">
              TRUST AND EQUITY
            </p>
            <p className="text-stone-800 font-normal text-sm leading-5 whitespace-pre-line">
              Organizations keep data in-network, enabling safer deployment for
              public-facing services where trust and accessibility matter most.
            </p>
          </div>
        </li>
      </ul>
    </div>
  );
};

export default Demo;
