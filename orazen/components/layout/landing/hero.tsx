"use client";

import { ScribbledArrowToRight } from "@/assets/svgs";
import { Button } from "@/components/ui/button";
import Link from "next/link";

const Hero = () => {
  return (
    <div className="relative flex h-[calc(70svh-64px-150px)] flex-row items-center overflow-hidden border-b border-dashed">
      <div className="z-10 flex flex-col gap-4">
        <div className="flex flex-row items-center gap-2 px-6">
          <div className="bg-muted/20 relative flex h-7 w-16 flex-row items-center gap-2 rounded-md border px-2">
            <span className="urbanist absolute right-3 text-sm font-semibold">
              48h
            </span>
          </div>
          <div className="flex flex-row items-center">
            <div className="bg-muted/20 h-1.5 w-1.5 border"></div>
            <div className="from-muted h-px w-40 bg-linear-to-r to-transparent"></div>
          </div>
        </div>
        <div className="instrument-serif flex flex-col gap-2 px-6 text-6xl">
          <h1 className="dark:text-primary-foreground/30 text-secondary-foreground/50">
            Build Safer{" "}
            <span className="dark:text-primary-foreground text-secondary-foreground">
              Digital Access
            </span>{" "}
            For
          </h1>
          <h2 className="dark:text-primary-foreground/30 text-secondary-foreground/50">
            <span className="dark:text-primary-foreground text-secondary-foreground">
              Everyone
            </span>{" "}
            with AI.
          </h2>
        </div>
        <div className="mt-4 flex flex-row gap-4 px-6">
          <Link href={"/dashboard"}>
            <Button>
              <span>Launch Dashboard</span>
            </Button>
          </Link>
          <div className="relative">
            <Link target="_blank" href={"/"}>
              <Button variant="secondary">
                <span>Theme Fit</span>
                <svg
                  height="32"
                  width="32"
                  viewBox="0 0 32 32"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <g fill="currentColor">
                    <path d="M16,2.345c7.735,0,14,6.265,14,14-.002,6.015-3.839,11.359-9.537,13.282-.7,.14-.963-.298-.963-.665,0-.473,.018-1.978,.018-3.85,0-1.312-.437-2.152-.945-2.59,3.115-.35,6.388-1.54,6.388-6.912,0-1.54-.543-2.783-1.435-3.762,.14-.35,.63-1.785-.14-3.71,0,0-1.173-.385-3.85,1.435-1.12-.315-2.31-.472-3.5-.472s-2.38,.157-3.5,.472c-2.677-1.802-3.85-1.435-3.85-1.435-.77,1.925-.28,3.36-.14,3.71-.892,.98-1.435,2.24-1.435,3.762,0,5.355,3.255,6.563,6.37,6.913-.403,.35-.77,.963-.893,1.872-.805,.368-2.818,.963-4.077-1.155-.263-.42-1.05-1.452-2.152-1.435-1.173,.018-.472,.665,.017,.927,.595,.332,1.277,1.575,1.435,1.978,.28,.787,1.19,2.293,4.707,1.645,0,1.173,.018,2.275,.018,2.607,0,.368-.263,.787-.963,.665-5.719-1.904-9.576-7.255-9.573-13.283,0-7.735,6.265-14,14-14Z" />
                  </g>
                </svg>
              </Button>
            </Link>
            <span className="jetbrains-mono text-muted-foreground/20 pointer-events-none absolute -top-10 left-40 size-full -rotate-34 text-[10px]">
              15+ guard scanners <br /> 150+ red-team probes <br /> reduced access barriers
            </span>
            <ScribbledArrowToRight className="text-muted-foreground/20 pointer-events-none absolute top-2 left-22 size-full rotate-190" />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Hero;
