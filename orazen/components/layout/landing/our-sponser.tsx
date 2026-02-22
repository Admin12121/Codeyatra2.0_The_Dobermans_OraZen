import {
  ModernCardContainer,
  ModernCardDescription,
  ModernCardTitle,
} from "@/components/ui/modern-card";
import { FancyBadgeWithBorders } from "@/components/ui/fancy-badges";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import Image from "next/image";
import Link from "next/link";
import React from "react";

interface Sponsor {
  name: string;
  image: string | null;
  description: string;
  imageClass: string;
  invert?: boolean;
  label?: string;
  link?: string;
}

const sponsors: Sponsor[] = [
  {
    name: "Built for Inclusive AI Services",
    label: "Startups, NGOs, Education, Public Platforms",
    imageClass: "h-20 w-40",
    image: null,
    description:
      "Orazen helps teams run safer AI services so more people can access digital information and services with confidence.",
    link: "mailto:admin@legions.dev?subject=Orazen%20Partnership",
  },
];

const OurSponser = () => {
  return (
    <div className="flex w-full flex-col">
      <div className="flex flex-col items-center border-b border-dashed py-4">
        <FancyBadgeWithBorders>Who It Is For</FancyBadgeWithBorders>
      </div>
      <div className="flex flex-col">
        {sponsors.map((sponsor, index) => (
          <div
            key={sponsor.name}
            className={cn(
              "grid grid-flow-row grid-cols-1 border-b border-dashed sm:grid-cols-3 md:h-[150px]",
            )}
          >
            <ModernCardContainer
              className={cn(
                "flex flex-col p-6 sm:col-span-2",
                index % 2 === 0 && "sm:order-1",
              )}
            >
              <ModernCardTitle label={sponsor.label}>
                {sponsor.name}
              </ModernCardTitle>
              <ModernCardDescription>
                {sponsor.description}
              </ModernCardDescription>
              {sponsor.link && (
                <Link className="mt-1" href={sponsor.link}>
                  <Button
                    variant={"secondary"}
                    size="xs"
                    className="bg-white text-neutral-900"
                  >
                    Talk to Us
                  </Button>
                </Link>
              )}
            </ModernCardContainer>
            <ModernCardContainer
              className={cn(
                index === sponsors.length - 1 && "!p-2",
                index % 2 === 0 ? "sm:border-r" : "sm:border-l",
                "flex flex-col items-center justify-center border-none p-6 sm:border-dashed",
              )}
            >
              {sponsor.image ? (
                <Image
                  className={cn(
                    "object-contain",
                    sponsor.invert && "invert dark:invert-0",
                    sponsor.imageClass,
                  )}
                  src={sponsor.image}
                  alt={sponsor.name}
                  width={254}
                  height={254}
                />
              ) : (
                <div className="bg-dashed flex h-full w-full items-center justify-center rounded-md px-10 py-5">
                  <span className="jetbrains-mono bg-background text-muted-foreground rounded-sm px-2 py-1 text-center text-xs">
                    Your Image Here
                  </span>
                </div>
              )}
            </ModernCardContainer>
          </div>
        ))}
      </div>
    </div>
  );
};

export default OurSponser;
