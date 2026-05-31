import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes } from "react";
import { cn } from "../../lib/cn";

const buttonVariants = cva(
  "inline-flex h-9 items-center justify-center gap-2 rounded-md border px-3 text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "border-slate-900 bg-slate-900 text-white hover:bg-slate-800",
        secondary: "border-slate-200 bg-white text-slate-900 hover:bg-slate-50",
        danger: "border-red-700 bg-red-700 text-white hover:bg-red-800"
      }
    },
    defaultVariants: {
      variant: "default"
    }
  }
);

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonVariants>;

export function Button({ className, variant, ...props }: ButtonProps) {
  return <button className={cn(buttonVariants({ variant }), className)} {...props} />;
}
