import Image from "next/image";
import Link from "next/link";

const Footer = () => {
  return (
    <footer className="mt-10 flex flex-col gap-10 px-4 md:px-6">
      <div className="flex flex-col-reverse items-start justify-between gap-8 md:flex-row md:items-center md:gap-0">
        <div className="flex max-w-80 flex-col justify-start gap-4">
          <div className="flex flex-col items-start gap-2">
            <Link
              aria-label="Go to home"
              className="m-0 flex w-fit flex-row items-center gap-3 py-2 hover:opacity-70"
              href="/"
            >
              <Image src="/official/logo.png" alt="logo" width={32} height={32} />
              Orazen
            </Link>
            <p className="text-sm font-normal text-muted-foreground">
              Orazen is a self-hosted AI safety platform designed to improve
              accessibility, inclusiveness, and equitable participation in
              AI-powered digital services.
            </p>
          </div>
          <p className="text-xs font-normal text-muted-foreground/80">
            Copyright 2026 | Orazen
          </p>
        </div>
      </div>
      <div className="text-center"></div>
    </footer>
  );
};

export default Footer;

