import Image from "next/image";
import * as React from "react";

import { cn } from "@/lib/format";

export const APP_ICONS = {
  shield: "/icons/shield.png",
  security: "/icons/security.png",
  scanner: "/icons/scanner.png",
  coding: "/icons/coding.png",
  github: "/icons/github.png",
  clone: "/icons/Clone.png",
  staticPass: "/icons/static-pass.png",
  semanticPass: "/icons/semantic-pass.png",
  fix: "/icons/fix.png",
  success: "/icons/success.png",
  failed: "/icons/failed.png",
  social: "/icons/social.png",
} as const;

export type AppIconName = keyof typeof APP_ICONS;
export type IconName = AppIconName;

const SIZES = {
  xs: 14,
  sm: 18,
  md: 24,
  lg: 32,
  xl: 48,
  "2xl": 64,
} as const;

export interface AppIconProps extends Omit<React.ImgHTMLAttributes<HTMLImageElement>, "src" | "width" | "height"> {
  name: AppIconName;
  size?: keyof typeof SIZES | number;
  className?: string;
  alt?: string;
  white?: boolean;
}

export function AppIcon({
  name,
  size = "md",
  className,
  alt = "",
  white = true,
  style,
  ...props
}: AppIconProps) {
  const pixelSize: number = typeof size === "number" ? size : (SIZES[size] ?? 24);
  const src = APP_ICONS[name];

  return (
    <Image
      src={src}
      alt={alt}
      width={pixelSize}
      height={pixelSize}
      className={cn(
        "inline-block shrink-0 object-contain align-middle",
        white && "brightness-0 invert",
        className,
      )}
      style={{
        filter: white ? "brightness(0) invert(1)" : undefined,
        ...style,
      }}
      unoptimized
      {...props}
    />
  );
}
