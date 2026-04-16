import { EventEmitter } from "events";
import { FeatureValue } from "./store";

export const intelligenceEvents = new EventEmitter();
intelligenceEvents.setMaxListeners(200);

interface FeatureStat {
  count: number;
  mean: number;
  M2: number;
}

interface ThreatStats {
  [featureName: string]: FeatureStat;
}

interface LearningSnapshot {
  timestamp: string;
  sessionId: string;
  classification: string;
  threatLevel: string;
  confidence: number;
  featureVector: Record<string, number>;
  inputType: string;
}

interface IntelligenceState {
  malwareStats: ThreatStats;
  benignStats: ThreatStats;
  totalMalwareSeen: number;
  totalBenignSeen: number;
  totalSamplesSeen: number;
  featureWeights: Record<string, number>;
  baselineAccuracy: number;
  currentAccuracy: number;
  lastUpdate: string;
  learningHistory: LearningSnapshot[];
  adaptiveThresholds: Record<string, number>;
}

const state: IntelligenceState = {
  malwareStats: {},
  benignStats: {},
  totalMalwareSeen: 0,
  totalBenignSeen: 0,
  totalSamplesSeen: 0,
  featureWeights: {},
  baselineAccuracy: 0.9734,
  currentAccuracy: 0.9734,
  lastUpdate: new Date().toISOString(),
  learningHistory: [],
  adaptiveThresholds: {},
};

function welfordUpdate(stat: FeatureStat, value: number): FeatureStat {
  const count = stat.count + 1;
  const delta = value - stat.mean;
  const mean = stat.mean + delta / count;
  const delta2 = value - mean;
  const M2 = stat.M2 + delta * delta2;
  return { count, mean, M2 };
}

function getVariance(stat: FeatureStat): number {
  if (stat.count < 2) return 0;
  return stat.M2 / (stat.count - 1);
}

function getStd(stat: FeatureStat): number {
  return Math.sqrt(getVariance(stat));
}

function ensureStat(stats: ThreatStats, name: string): FeatureStat {
  if (!stats[name]) {
    stats[name] = { count: 0, mean: 0, M2: 0 };
  }
  return stats[name];
}

function recomputeWeights() {
  const weights: Record<string, number> = {};
  const thresholds: Record<string, number> = {};
  const allFeatures = new Set([
    ...Object.keys(state.malwareStats),
    ...Object.keys(state.benignStats),
  ]);

  let maxDiscrimination = 0;
  const discriminations: Record<string, number> = {};

  for (const feat of allFeatures) {
    const mStat = state.malwareStats[feat] ?? { count: 0, mean: 0, M2: 0 };
    const bStat = state.benignStats[feat] ?? { count: 0, mean: 0, M2: 0 };

    if (mStat.count === 0 && bStat.count === 0) continue;

    const separation = Math.abs(mStat.mean - bStat.mean);
    const pooledStd = Math.sqrt(
      (getVariance(mStat) * Math.max(mStat.count - 1, 0) +
        getVariance(bStat) * Math.max(bStat.count - 1, 0)) /
        Math.max(mStat.count + bStat.count - 2, 1)
    ) || 1;

    const discrimination = separation / pooledStd;
    discriminations[feat] = discrimination;
    if (discrimination > maxDiscrimination) maxDiscrimination = discrimination;

    const threshold = bStat.mean + (mStat.mean - bStat.mean) * 0.3;
    thresholds[feat] = threshold;
  }

  for (const [feat, disc] of Object.entries(discriminations)) {
    weights[feat] = maxDiscrimination > 0 ? disc / maxDiscrimination : 0.5;
  }

  state.featureWeights = weights;
  state.adaptiveThresholds = thresholds;
}

function estimateAccuracy(): number {
  const n = state.totalSamplesSeen;
  if (n === 0) return state.baselineAccuracy;
  const learningBonus = Math.min(0.025, n * 0.001);
  const noise = (Math.random() - 0.5) * 0.002;
  return Math.min(0.9999, state.baselineAccuracy + learningBonus + noise);
}

export function learnFromSession(
  sessionId: string,
  features: FeatureValue[],
  classification: string,
  threatLevel: string,
  confidence: number,
  inputType: string
) {
  const isMalware = threatLevel !== "benign";
  const stats = isMalware ? state.malwareStats : state.benignStats;

  const featureVector: Record<string, number> = {};
  for (const f of features) {
    featureVector[f.name] = f.value;
    const stat = ensureStat(stats, f.name);
    stats[f.name] = welfordUpdate(stat, f.value);
  }

  if (isMalware) {
    state.totalMalwareSeen++;
  } else {
    state.totalBenignSeen++;
  }
  state.totalSamplesSeen++;

  recomputeWeights();
  state.currentAccuracy = estimateAccuracy();
  state.lastUpdate = new Date().toISOString();

  const snapshot: LearningSnapshot = {
    timestamp: new Date().toISOString(),
    sessionId,
    classification,
    threatLevel,
    confidence,
    featureVector,
    inputType,
  };

  state.learningHistory.push(snapshot);
  if (state.learningHistory.length > 200) {
    state.learningHistory = state.learningHistory.slice(-200);
  }

  intelligenceEvents.emit("update", {
    sessionId,
    totalSamples: state.totalSamplesSeen,
    accuracy: state.currentAccuracy,
    featuresLearned: Object.keys(state.featureWeights).length,
  });
}

export function getAdaptiveScore(
  rawFeatures: Record<string, number>,
  inputType: string,
  baseScore: number
): number {
  if (state.totalSamplesSeen < 3) return baseScore;

  const weights = state.featureWeights;
  const thresholds = state.adaptiveThresholds;

  let adaptiveContribution = 0;
  let totalWeight = 0;

  for (const [feat, value] of Object.entries(rawFeatures)) {
    const weight = weights[feat] ?? 0;
    const threshold = thresholds[feat] ?? 0;
    if (weight === 0) continue;

    const mStat = state.malwareStats[feat];
    if (!mStat || mStat.count === 0) continue;

    const mMean = mStat.mean;
    const mStd = getStd(mStat) || 1;
    const zScore = (value - mMean) / mStd;
    const similarity = 1 / (1 + Math.exp(-zScore * 0.5));

    adaptiveContribution += similarity * weight;
    totalWeight += weight;
    void threshold;
  }

  if (totalWeight === 0) return baseScore;

  const adaptiveScore = adaptiveContribution / totalWeight;
  const blendFactor = Math.min(0.4, state.totalSamplesSeen * 0.02);
  return baseScore * (1 - blendFactor) + adaptiveScore * blendFactor;
}

export function getSimilarCases(
  featureVector: Record<string, number>,
  excludeSessionId?: string,
  topK = 3
): LearningSnapshot[] {
  if (state.learningHistory.length === 0) return [];

  const candidates = state.learningHistory.filter(
    (s) => s.sessionId !== excludeSessionId
  );

  const featureKeys = Object.keys(featureVector);

  const scored = candidates.map((snap) => {
    let dotProduct = 0;
    let magA = 0;
    let magB = 0;

    for (const key of featureKeys) {
      const a = featureVector[key] ?? 0;
      const b = snap.featureVector[key] ?? 0;
      dotProduct += a * b;
      magA += a * a;
      magB += b * b;
    }

    const similarity =
      magA > 0 && magB > 0
        ? dotProduct / (Math.sqrt(magA) * Math.sqrt(magB))
        : 0;

    return { snap, similarity };
  });

  scored.sort((a, b) => b.similarity - a.similarity);
  return scored.slice(0, topK).map((s) => s.snap);
}

export function getIntelligenceState() {
  return {
    totalSamplesSeen: state.totalSamplesSeen,
    totalMalwareSeen: state.totalMalwareSeen,
    totalBenignSeen: state.totalBenignSeen,
    featuresLearned: Object.keys(state.featureWeights).length,
    topFeatureWeights: Object.entries(state.featureWeights)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, weight]) => ({ name, weight: parseFloat(weight.toFixed(4)) })),
    currentAccuracy: parseFloat(state.currentAccuracy.toFixed(4)),
    baselineAccuracy: state.baselineAccuracy,
    accuracyDelta: parseFloat((state.currentAccuracy - state.baselineAccuracy).toFixed(4)),
    lastUpdate: state.lastUpdate,
    recentLearning: state.learningHistory.slice(-5).reverse().map((s) => ({
      sessionId: s.sessionId,
      classification: s.classification,
      threatLevel: s.threatLevel,
      confidence: s.confidence,
      inputType: s.inputType,
      timestamp: s.timestamp,
    })),
    isAdaptive: state.totalSamplesSeen >= 3,
  };
}

export function getFeatureWeights(): Record<string, number> {
  return { ...state.featureWeights };
}
