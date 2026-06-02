import { Link } from "@tanstack/react-router";
import { Radar } from "lucide-react";
import { Button } from "../components/ui";
import { useT } from "../i18n";

export function NotFoundPage() {
  const t = useT();
  return (
    <div className="app-atmosphere relative grid min-h-screen place-items-center p-6">
      <div className="relative z-10 text-center">
        <Radar className="mx-auto h-10 w-10 text-signal" />
        <div className="display readout mt-6 text-6xl font-bold text-ink">404</div>
        <p className="mt-2 text-sm text-muted">{t("This sector of the deck doesn’t exist.")}</p>
        <Link to="/" className="mt-6 inline-block">
          <Button variant="primary" size="md">
            {t("Return to overview")}
          </Button>
        </Link>
      </div>
    </div>
  );
}
