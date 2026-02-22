import Image from "next/image";

const Banner = () => {
  return (
    <div className="flex lg:flex-row mt-30 flex-col px-4 lg:px-6 py-6 gap-6 border-y  bg-stone-0 items-center justify-between border-dashed">
      <Image
        src="/official/protector.png"
        alt="Orazen Logo"
        width={100}
        height={100}
      />
      <div className="flex flex-col gap-1 flex-1 ">
        <p className="text-stone-800 font-normal text-2xl cooper text-center lg:text-start">
          Safer AI interactions create more inclusive digital services.
        </p>
        <p className="text-stone-500 font-normal text-base text-center lg:text-start lg:whitespace-pre-line whitespace-normal">
          Orazen reduces trust barriers so people can safely access information,
          complete services, and participate equitably in digital environments.
        </p>
      </div>
      <a
        type="button"
        className=" cursor-pointer box-border  flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none disabled:shadow-none disabled:opacity-50 disabled:cursor-not-allowed gap-x-1 active:shadow-none active:scale-95 text-sm leading-5 rounded-xl px-4 py-1.5 h-8
        text-stone-50
        bg-indigo-500class=
        border border-indigo-600
        hover:bg-indigo-600

        dark:text-stone-900
        bg-indigo-500

        dark:disabled:bg-indigo-400
        dark:hover:disabled:bg-indigo-400
      "
        translate="no"
        href="/login"
      >
        Start Free Trial
      </a>
    </div>
  );
};

export default Banner;

