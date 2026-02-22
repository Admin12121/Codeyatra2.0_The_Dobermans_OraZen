"use client";
import styles from "./style.module.css";
import { useEffect, useState, useSyncExternalStore } from "react";
import { motion } from "framer-motion";
import { opacity, slideUp } from "./anim";

const words = [
  "Namaste",
  "Jwajalapa",
  "Ciao",
  "Olà",
  "やあ",
  "Hallå",
  "Guten tag",
  "Hallo",
];

function subscribeToResize(callback: () => void) {
  window.addEventListener("resize", callback);
  return () => window.removeEventListener("resize", callback);
}

function getSnapshot() {
  return `${window.innerWidth}x${window.innerHeight}`;
}

function getServerSnapshot() {
  return "0x0";
}

function useWindowDimensions() {
  const snapshot = useSyncExternalStore(
    subscribeToResize,
    getSnapshot,
    getServerSnapshot,
  );
  const [w, h] = snapshot.split("x").map(Number);
  return { width: w, height: h };
}

export default function Index() {
  const [index, setIndex] = useState(0);
  const dimension = useWindowDimensions();

  useEffect(() => {
    if (index == words.length - 1) return;
    const timeout = setTimeout(
      () => {
        setIndex(index + 1);
      },
      index == 0 ? 1000 : 150,
    );
    return () => clearTimeout(timeout);
  }, [index]);

  const initialPath = `M0 0 L${dimension.width} 0 L${dimension.width} ${dimension.height} Q${dimension.width / 2} ${dimension.height + 300} 0 ${dimension.height}  L0 0`;
  const targetPath = `M0 0 L${dimension.width} 0 L${dimension.width} ${dimension.height} Q${dimension.width / 2} ${dimension.height} 0 ${dimension.height}  L0 0`;

  const curve = {
    initial: {
      d: initialPath,
      transition: {
        duration: 0.7,
        ease: [0.76, 0, 0.24, 1] as [number, number, number, number],
      },
    },
    exit: {
      d: targetPath,
      transition: {
        duration: 0.7,
        ease: [0.76, 0, 0.24, 1] as [number, number, number, number],
        delay: 0.3,
      },
    },
  };

  return (
    <motion.div
      variants={slideUp}
      initial="initial"
      exit="exit"
      className={styles.introduction}
    >
      {dimension.width > 0 && (
        <>
          <motion.p variants={opacity} initial="initial" animate="enter">
            <span></span>
            {words[index]}
          </motion.p>
          <svg>
            <motion.path
              variants={curve}
              initial="initial"
              exit="exit"
            ></motion.path>
          </svg>
        </>
      )}
    </motion.div>
  );
}
