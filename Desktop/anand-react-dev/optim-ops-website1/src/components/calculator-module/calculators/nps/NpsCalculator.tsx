import { useMemo, useState } from "react";
import {
  TrendingUp,
  AlertCircle,
  PiggyBank,
  Wallet,
  Calendar,
  Percent,
  Calculator,
} from "lucide-react";

type Errors = {
  amount?: string;
  returnRate?: string;
  age?: string;
  retirementAge?: string;
  annuityPercent?: string;
  annuityRate?: string;
};

export default function NpsCalculator() {
  const [monthlyInvestment, setMonthlyInvestment] = useState<string>("");
  const [returnRate, setReturnRate] = useState<string>("");
  const [age, setAge] = useState<string>("");
  const [retirementAge, setRetirementAge] = useState<string>("");
  const [annuityPercent, setAnnuityPercent] = useState<string>("");
  const [annuityRate, setAnnuityRate] = useState<string>("");

  const [errors, setErrors] = useState<Errors>({});
  const [showResult, setShowResult] = useState(false);

  /* ---------------- VALIDATION ---------------- */
  const validate = () => {
    const newErrors: Errors = {};
    const amount = Number(monthlyInvestment);
    const rate = Number(returnRate);
    const currentAge = Number(age);
    const retAge = Number(retirementAge);
    const annPct = Number(annuityPercent);
    const annRate = Number(annuityRate);

    if (!monthlyInvestment || amount <= 0)
      newErrors.amount = "Enter valid amount";

    if (!returnRate || rate < 5 || rate > 15)
      newErrors.returnRate = "Rate: 5%-15%";

    if (!age || currentAge < 18 || currentAge > 60)
      newErrors.age = "Age: 18-60 years";

    if (!retirementAge || retAge < 60 || retAge > 75)
      newErrors.retirementAge = "Age: 60-75 years";

    if (currentAge && retAge && currentAge >= retAge)
      newErrors.retirementAge = "Must be > current age";

    if (!annuityPercent || annPct < 40) newErrors.annuityPercent = "Min 40%";

    if (!annuityRate || annRate < 4 || annRate > 10)
      newErrors.annuityRate = "Rate: 4%-10%";

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  /* ---------------- CALCULATION ---------------- */
  const result = useMemo(() => {
    if (!showResult) return null;

    const investment = Number(monthlyInvestment);
    const rate = Number(returnRate);
    const currentAge = Number(age);
    const retAge = Number(retirementAge);
    const annPct = Number(annuityPercent);
    const annRate = Number(annuityRate);
    const years = retAge - currentAge;
    const months = years * 12;
    const monthlyRate = rate / 100 / 12;

    let corpus = 0;
    for (let i = 0; i < months; i++) {
      corpus = (corpus + investment) * (1 + monthlyRate);
    }

    const invested = investment * months;
    const interest = corpus - invested;

    const annuityValue = (corpus * annPct) / 100;
    const lumpSum = corpus - annuityValue;

    // ✅ EXISTING SYSTEM LOGIC
    const monthlyPension = (annuityValue * annRate) / 100 / 12;

    return {
      invested,
      interest,
      corpus,
      lumpSum,
      annuityValue,
      monthlyPension,
      years,
    };
  }, [
    showResult,
    monthlyInvestment,
    returnRate,
    age,
    retirementAge,
    annuityPercent,
    annuityRate,
  ]);

  const formatCurrency = (num: number) => {
    return num.toLocaleString("en-IN", {
      maximumFractionDigits: 0,
    });
  };

  /* ---------------- UI ---------------- */
  return (
    <div className="min-h-screenbg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50  p-4 flex items-center justify-center">
      <div className="w-full max-w-2xl">
        {/* HEADER */}
        <div className=" mt-10 p-4 text-center bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-3xl mb-6">
          <div className="flex items-center  justify-center gap-2 mb-2">
            <Calculator className="w-6 h-6 text-white" />
            <h1 className="text-3xl font-bold text-white">NPS Calculator</h1>
          </div>
          <p className="text-white text-sm">
            Plan your retirement with National Pension System
          </p>
        </div>

        {/* FORM */}
        <div className="bg-white rounded-xl shadow-xl p-6 mb-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Monthly Investment */}
            <div>
              <label className="flex items-center gap-1.5 text-sm font-semibold text-gray-700 mb-2">
                <PiggyBank className="w-3.5 h-3.5" />
                Monthly Investment
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 font-medium">
                  ₹
                </span>
                <input
                  type="number"
                  placeholder="5,000"
                  value={monthlyInvestment}
                  onChange={(e) => {
                    setMonthlyInvestment(e.target.value);
                    setShowResult(false);
                    setErrors({ ...errors, amount: undefined });
                  }}
                  className={`w-full pl-8 pr-4 py-2.5 border-2 rounded-lg focus:ring-2 focus:ring-indigo-200 transition-all ${
                    errors.amount
                      ? "border-red-500"
                      : "border-gray-200 focus:border-indigo-500"
                  }`}
                />
              </div>
              {errors.amount && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.amount}</span>
                </div>
              )}
            </div>

            {/* Expected Return */}
            <div>
              <label className="flex items-center gap-1.5 text-sm font-semibold text-gray-700 mb-2">
                <Percent className="w-3.5 h-3.5" />
                Expected Return (PA)
              </label>
              <div className="relative">
                <input
                  type="number"
                  placeholder="8 - 12"
                  value={returnRate}
                  onChange={(e) => {
                    setReturnRate(e.target.value);
                    setShowResult(false);
                    setErrors({ ...errors, returnRate: undefined });
                  }}
                  className={`w-full pr-10 pl-4 py-2.5 border-2 rounded-lg focus:ring-2 focus:ring-indigo-200 transition-all ${
                    errors.returnRate
                      ? "border-red-500"
                      : "border-gray-200 focus:border-indigo-500"
                  }`}
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 font-medium">
                  %
                </span>
              </div>
              {errors.returnRate && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.returnRate}</span>
                </div>
              )}
            </div>

            {/* Current Age */}
            <div>
              <label className="flex items-center gap-1.5 text-sm font-semibold text-gray-700 mb-2">
                <Calendar className="w-3.5 h-3.5" />
                Current Age
              </label>
              <div className="relative">
                <input
                  type="number"
                  placeholder="25 - 40"
                  value={age}
                  onChange={(e) => {
                    setAge(e.target.value);
                    setShowResult(false);
                    setErrors({ ...errors, age: undefined });
                  }}
                  className={`w-full pr-16 pl-4 py-2.5 border-2 rounded-lg focus:ring-2 focus:ring-indigo-200 transition-all ${
                    errors.age
                      ? "border-red-500"
                      : "border-gray-200 focus:border-indigo-500"
                  }`}
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 text-sm">
                  years
                </span>
              </div>
              {errors.age && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.age}</span>
                </div>
              )}
            </div>

            {/* Retirement Age */}
            <div>
              <label className="flex items-center gap-1.5 text-sm font-semibold text-gray-700 mb-2">
                <Calendar className="w-3.5 h-3.5" />
                Retirement Age
              </label>
              <div className="relative">
                <input
                  type="number"
                  placeholder="60 - 65"
                  value={retirementAge}
                  onChange={(e) => {
                    setRetirementAge(e.target.value);
                    setShowResult(false);
                    setErrors({ ...errors, retirementAge: undefined });
                  }}
                  className={`w-full pr-16 pl-4 py-2.5 border-2 rounded-lg focus:ring-2 focus:ring-indigo-200 transition-all ${
                    errors.retirementAge
                      ? "border-red-500"
                      : "border-gray-200 focus:border-indigo-500"
                  }`}
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 text-sm">
                  years
                </span>
              </div>
              {errors.retirementAge && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.retirementAge}</span>
                </div>
              )}
            </div>

            {/* Annuity Percentage */}
            <div>
              <label className="flex items-center gap-1.5 text-sm font-semibold text-gray-700 mb-2">
                <Wallet className="w-3.5 h-3.5" />
                Annuity Percentage
              </label>
              <div className="relative">
                <input
                  type="number"
                  placeholder="40 - 100"
                  value={annuityPercent}
                  onChange={(e) => {
                    setAnnuityPercent(e.target.value);
                    setShowResult(false);
                    setErrors({ ...errors, annuityPercent: undefined });
                  }}
                  className={`w-full pr-10 pl-4 py-2.5 border-2 rounded-lg focus:ring-2 focus:ring-indigo-200 transition-all ${
                    errors.annuityPercent
                      ? "border-red-500"
                      : "border-gray-200 focus:border-indigo-500"
                  }`}
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 font-medium">
                  %
                </span>
              </div>
              {errors.annuityPercent && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.annuityPercent}</span>
                </div>
              )}
            </div>

            {/* Annuity Rate */}
            <div>
              <label className="flex items-center gap-1.5 text-sm font-semibold text-gray-700 mb-2">
                <Percent className="w-3.5 h-3.5" />
                Annuity Rate (PA)
              </label>
              <div className="relative">
                <input
                  type="number"
                  placeholder="4 - 8"
                  value={annuityRate}
                  onChange={(e) => {
                    setAnnuityRate(e.target.value);
                    setShowResult(false);
                    setErrors({ ...errors, annuityRate: undefined });
                  }}
                  className={`w-full pr-10 pl-4 py-2.5 border-2 rounded-lg focus:ring-2 focus:ring-indigo-200 transition-all ${
                    errors.annuityRate
                      ? "border-red-500"
                      : "border-gray-200 focus:border-indigo-500"
                  }`}
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 font-medium">
                  %
                </span>
              </div>
              {errors.annuityRate && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.annuityRate}</span>
                </div>
              )}
            </div>
          </div>

          {/* BUTTON */}
          <button
            onClick={() => {
              if (validate()) setShowResult(true);
            }}
            className="w-full bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white py-3 rounded-lg mt-6 font-semibold shadow-lg transition-all transform hover:scale-[1.02] flex items-center justify-center gap-2"
          >
            <TrendingUp className="w-4 h-4" />
            Calculate NPS Returns
          </button>
        </div>

        {/* RESULT - INTERACTIVE REPORT */}
        {result && (
          <div className="bg-white rounded-xl shadow-lg overflow-hidden p-4">
            {/* Header */}
            <div className="mb-4">
              <h3 className="text-lg font-bold text-gray-800">
                NPS Projection
              </h3>
              <p className="text-xs text-gray-500">
                {result.years} years investment period
              </p>
            </div>
            <div className="flex items-center justify-between w-full">
              {/* LEFT SIDE : Invested + Interest */}
              <div className="flex items-center gap-6">
                {/* Invested */}
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 rounded-full bg-blue-500"></div>
                  <div>
                    <p className="text-xl text-gray-600 mb-1">Invested</p>
                    <p className="text-sm font-semibold text-blue-700">
                      ₹{formatCurrency(result.invested)}
                    </p>
                  </div>
                </div>

                {/* + */}
                <span className="text-lg font-semibold text-gray-500">+</span>

                {/* Interest */}
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 rounded-full bg-purple-500"></div>
                  <div>
                    <p className="text-xl text-gray-600 mb-1">Interest</p>
                    <p className="text-sm font-semibold text-purple-700">
                      ₹{formatCurrency(result.interest)}
                    </p>
                  </div>
                </div>
              </div>
              <span className="text-lg font-semibold text-gray-500">=</span>

              {/* RIGHT SIDE : Maturity */}
              <div className="text-right">
                <p className="text-xl text-gray-600 mb-1">Maturity</p>
                <p className="text-sm font-semibold text-green-700">
                  ₹{formatCurrency(result.corpus)}
                </p>
              </div>
            </div>

            {/* Circular Chart + Stats */}
            <div className="flex flex-col lg:flex-row items-center gap-10 mt-8">
              {/* ================= CIRCULAR CHART ================= */}
              <div className="relative w-48 h-48">
                {/* Center Text */}
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center">
                    <p className="text-xs text-gray-500 mb-1">
                      Maturity Amount
                    </p>
                    <p className="text-2xl font-bold text-gray-800">
                      ₹{formatCurrency(result.corpus)}
                    </p>
                  </div>
                </div>

                {/* Donut */}
                <svg className="w-full h-full transform -rotate-90">
                  {/* Background ring */}
                  <circle
                    cx="96"
                    cy="96"
                    r="80"
                    stroke="#e5e7eb"
                    strokeWidth="14"
                    fill="none"
                  />

                  {/* Invested */}
                  <circle
                    cx="96"
                    cy="96"
                    r="80"
                    stroke="#3b82f6"
                    strokeWidth="14"
                    fill="none"
                    strokeDasharray={`${
                      (result.invested / result.corpus) * 502
                    } 502`}
                  />

                  {/* Interest */}
                  <circle
                    cx="96"
                    cy="96"
                    r="80"
                    stroke="#8b5cf6"
                    strokeWidth="14"
                    fill="none"
                    strokeDasharray={`${
                      (result.interest / result.corpus) * 502
                    } 502`}
                    strokeDashoffset={
                      -((result.invested / result.corpus) * 502)
                    }
                  />
                </svg>
              </div>

              {/* ================= RIGHT SIDE DETAILS ================= */}
              <div className="flex-1 space-y-6 w-full">
                {/* Invested + Interest Row */}

                {/* Lump Sum & Annuity */}
                <div className="grid grid-cols-2 gap-6 border-b pb-4">
                  <div>
                    <p className="text-xs text-gray-500">Lump sum value</p>
                    <p className="text-lg font-bold text-gray-800">
                      ₹{formatCurrency(result.lumpSum)}
                    </p>
                  </div>

                  <div>
                    <p className="text-xs text-gray-500">Annuity value</p>
                    <p className="text-lg font-bold text-gray-800">
                      ₹{formatCurrency(result.annuityValue)}
                    </p>
                  </div>
                </div>

                {/* Monthly Pension (Highlighted but NOT card) */}
                <div className="pt-2">
                  <p className="text-xs text-gray-500 mb-1">Monthly Pension</p>
                  <p className="text-2xl font-bold text-emerald-600">
                    ₹{formatCurrency(result.monthlyPension)}
                  </p>
                  <p className="text-xs text-gray-400 mt-1">
                    For 20 years post-retirement
                  </p>
                </div>
              </div>
            </div>

            {/* Retirement Distribution */}
            {/* <div className=" grid grid-row-2 gap-3 mb-2">
              <div className="bg-orange-50 rounded-lg p-1 border border-orange-200">
                <p className="text-xs text-gray-700 mb-1">Lump Sum</p>
                <p className="text-xl font-bold text-orange-700">
                  ₹{formatCurrency(result.lumpSum)}
                </p>
              </div>
              <div className="bg-teal-50 rounded-lg p-1 border border-teal-200">
                <p className="text-xs text-gray-700 mb-1">Annuity</p>
                <p className="text-xl font-bold text-teal-700">
                  ₹{formatCurrency(result.annuityValue)}
                </p>
              </div>
            </div> */}

            {/* Monthly Pension */}

            {/* Note */}
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 mb-3">
              <p className="text-xs text-amber-800">
                Projections are indicative. Minimum 40% must be used for
                annuity.
              </p>
            </div>

            {/* Recalculate Button */}
            <button
              onClick={() => setShowResult(false)}
              className="w-full bg-gray-100 hover:bg-gray-200 text-gray-700 py-2 rounded-lg font-medium text-sm"
            >
              Recalculate
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
