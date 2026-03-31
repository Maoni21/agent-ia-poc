import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

const severityConfig = {
  CRITICAL: {
    className: "bg-red-600 text-white hover:bg-red-700 border-red-600",
    label: "CRITICAL",
  },
  HIGH: {
    className: "bg-orange-500 text-white hover:bg-orange-600 border-orange-500",
    label: "HIGH",
  },
  MEDIUM: {
    className: "bg-amber-400 text-amber-900 hover:bg-amber-500 border-amber-400",
    label: "MEDIUM",
  },
  LOW: {
    className: "bg-gray-200 text-gray-700 hover:bg-gray-300 border-gray-200 dark:bg-gray-700 dark:text-gray-200",
    label: "LOW",
  },
  INFO: {
    className: "bg-blue-100 text-blue-800 hover:bg-blue-200 border-blue-100 dark:bg-blue-900 dark:text-blue-200",
    label: "INFO",
  },
}

export function SeverityBadge({ severity, className }) {
  const config = severityConfig[severity?.toUpperCase()] || severityConfig.INFO
  return (
    <Badge className={cn(config.className, className)}>
      {config.label}
    </Badge>
  )
}
