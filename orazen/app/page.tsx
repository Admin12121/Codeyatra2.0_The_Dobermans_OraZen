"use client";
import { useEffect, useState } from "react";
import Preloader from "@/components/layout/preloader";
import { AnimatePresence, motion } from "framer-motion";
import Banner from "@/components/layout/landing/banner";
import Demo from "@/components/layout/landing/demo";
import Features from "@/components/layout/landing/features";
import Footer from "@/components/layout/landing/footer";
import Header from "@/components/layout/landing/header";
import Hero from "@/components/layout/landing/hero";
import OurSponser from "@/components/layout/landing/our-sponser";
import Why from "@/components/layout/landing/why";
import Pricing from "@/components/layout/landing/pricing";

export default function Page() {
  const [isLoading, setIsLoading] = useState(true);
  useEffect(() => {
    document.body.style.overflow = "hidden";
    setTimeout(() => {
      setIsLoading(false);
      document.body.style.cursor = "default";
      document.body.style.overflow = "";
      window.scrollTo(0, 0);
    }, 2000);
  }, []);

  return (
    <main className="new-container relative border-none! sm:border-dashed!">
      <AnimatePresence mode="wait">
        {isLoading && <Preloader />}
      </AnimatePresence>
      <motion.div
        className="w-full"
        initial={{ y: 100, opacity: 0 }}
        animate={
          !isLoading
            ? {
                y: 0,
                opacity: 1,
                transition: {
                  duration: 0.8,
                  ease: [0.76, 0, 0.24, 1],
                  delay: 0.2,
                },
              }
            : {}
        }
      >
        <Header />
        <Hero />
        <Features />
        <Demo />
        <Why />
        <OurSponser />
        <Pricing />
        <Banner />
        <Footer />
      </motion.div>
    </main>
  );
}
