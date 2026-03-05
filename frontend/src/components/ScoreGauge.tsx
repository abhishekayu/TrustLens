interface ScoreGaugeProps {
  score: number | null
  size?: number
}

function getScoreColor(score: number): string {
  if (score >= 75) return '#00ff41'
  if (score >= 50) return '#ffff00'
  if (score >= 25) return '#ff8c00'
  return '#ff0040'
}

function getRiskLabel(score: number): string {
  if (score >= 75) return 'SAFE'
  if (score >= 50) return 'LOW RISK'
  if (score >= 25) return 'SUSPICIOUS'
  return 'HIGH RISK'
}

function getGlowClass(score: number): string {
  if (score >= 75) return 'glow-green'
  if (score >= 50) return 'glow-yellow'
  return 'glow-red'
}

export default function ScoreGauge({ score, size = 180 }: ScoreGaugeProps) {
  if (score === null || score === undefined) {
    return (
      <div className="flex items-center justify-center" style={{ width: size, height: size }}>
        <div className="w-16 h-16 border-2 border-[#1b2838] border-t-[#00ff41] rounded-full animate-spin" />
      </div>
    )
  }

  const radius = 45
  const circumference = 2 * Math.PI * radius
  const progress = Math.max(0, Math.min(100, score)) / 100
  const dashOffset = circumference * (1 - progress)
  const color = getScoreColor(score)
  const label = getRiskLabel(score)
  const glowClass = getGlowClass(score)

  return (
    <div className="flex flex-col items-center gap-3">
      <svg width={size} height={size} viewBox="0 0 100 100" className="transform -rotate-90">
        {/* Background circle */}
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke="#1b2838"
          strokeWidth="6"
        />
        {/* Tick marks */}
        {Array.from({ length: 40 }).map((_, i) => {
          const angle = (i / 40) * 2 * Math.PI - Math.PI / 2
          const inner = 38
          const outer = 41
          return (
            <line
              key={i}
              x1={50 + inner * Math.cos(angle)}
              y1={50 + inner * Math.sin(angle)}
              x2={50 + outer * Math.cos(angle)}
              y2={50 + outer * Math.sin(angle)}
              stroke="#1b2838"
              strokeWidth="0.5"
            />
          )
        })}
        {/* Progress circle */}
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          style={{
            transition: 'stroke-dashoffset 1.2s cubic-bezier(0.16, 1, 0.3, 1), stroke 0.5s ease',
            filter: `drop-shadow(0 0 8px ${color}60) drop-shadow(0 0 16px ${color}30)`,
          }}
        />
        {/* Score text */}
        <text
          x="50" y="46"
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-white"
          style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono)', transform: 'rotate(90deg)', transformOrigin: '50% 50%' }}
        >
          {Math.round(score)}
        </text>
        <text
          x="50" y="58"
          textAnchor="middle"
          dominantBaseline="central"
          style={{ fontSize: '5px', fontWeight: 500, fontFamily: 'var(--font-mono)', transform: 'rotate(90deg)', transformOrigin: '50% 50%', fill: '#484f58' }}
        >
          /100
        </text>
      </svg>
      <div className="text-center">
        <span
          className={`font-mono text-[11px] font-bold px-3 py-1 rounded border ${glowClass}`}
          style={{ backgroundColor: `${color}10`, color, borderColor: `${color}30` }}
        >
          {label}
        </span>
      </div>
    </div>
  )
}
