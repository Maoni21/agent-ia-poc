import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

const statusConfig = {
  running: {
    className: "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900 dark:text-blue-200",
    pulse: true,
    label: "Running",
  },
  completed: {
    className: "bg-green-100 text-green-800 border-green-200 dark:bg-green-900 dark:text-green-200",
    label: "Completed",
  },
  failed: {
    className: "bg-red-100 text-red-800 border-red-200 dark:bg-red-900 dark:text-red-200",
    label: "Failed",
  },
  pending: {
    className: "bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900 dark:text-yellow-200",
    label: "Pending",
  },
  cancelled: {
    className: "bg-gray-100 text-gray-600 border-gray-200 dark:bg-gray-800 dark:text-gray-300",
    label: "Cancelled",
  },
  open: {
    className: "bg-red-100 text-red-800 border-red-200 dark:bg-red-900 dark:text-red-200",
    label: "Open",
  },
  fixed: {
    className: "bg-green-100 text-green-800 border-green-200 dark:bg-green-900 dark:text-green-200",
    label: "Fixed",
  },
  ignored: {
    className: "bg-gray-100 text-gray-600 border-gray-200 dark:bg-gray-800 dark:text-gray-300",
    label: "Ignored",
  },
}

export function StatusBadge({ status, className }) {
  const config = statusConfig[status?.toLowerCase()] || {
    className: "bg-gray-100 text-gray-600 border-gray-200",
    label: status || "Unknown",
  }

  return (
    <Badge
      className={cn(
        config.className,
        config.pulse && "animate-pulse",
        className
      )}
    >
      {config.label}
    </Badge>
  )
}
