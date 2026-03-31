import { cn } from "@/lib/utils"

function getCVSSColor(score) {
  if (score >= 9.0) return "bg-red-600"
  if (score >= 7.0) return "bg-orange-500"
  if (score >= 4.0) return "bg-amber-400"
  if (score >= 0.1) return "bg-green-500"
  return "bg-gray-300"
}

function getCVSSLabel(score) {
  if (score >= 9.0) return "Critical"
  if (score >= 7.0) return "High"
  if (score >= 4.0) return "Medium"
  if (score >= 0.1) return "Low"
  return "None"
}

export function CVSSMeter({ score, className }) {
  const numScore = parseFloat(score) || 0
  const percentage = (numScore / 10) * 100
  const color = getCVSSColor(numScore)
  const label = getCVSSLabel(numScore)

  return (
    <div className={cn("space-y-1", className)}>
      <div className="flex justify-between items-center text-sm">
        <span className="text-muted-foreground">CVSS Score</span>
        <span className="font-bold">{numScore.toFixed(1)}/10 — {label}</span>
      </div>
      <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all", color)}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  )
}
