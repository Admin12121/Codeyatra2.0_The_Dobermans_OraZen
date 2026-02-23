import Image from "next/image";

const Banner = () => {
  return (
    <div className="mt-30 flex flex-col items-center justify-between gap-6 border-y border-dashed bg-background px-4 py-6 lg:flex-row lg:px-6">
      <Image
        src="/official/protector.png"
        alt="Orazen Logo"
        width={100}
        height={100}
      />
      <div className="flex flex-1 flex-col gap-1">
        <p className="cooper text-center text-2xl font-normal text-foreground lg:text-start">
          Safer AI interactions create more inclusive digital services.
        </p>
        <p className="text-center text-base font-normal text-muted-foreground whitespace-normal lg:text-start lg:whitespace-pre-line">
          Orazen reduces trust barriers so people can safely access information,
          complete services, and participate equitably in digital environments.
        </p>
      </div>
      <a
        type="button"
        className="inline-flex h-9 cursor-pointer items-center justify-center gap-x-1 whitespace-nowrap rounded-xl border border-primary/40 bg-primary px-4 py-1.5 text-center font-mono text-sm font-semibold uppercase leading-5 text-primary-foreground transition-colors duration-150 hover:bg-primary/90"
        translate="no"
        href="/login"
      >
        Start Free Trial
      </a>
    </div>
  );
};

export default Banner;

