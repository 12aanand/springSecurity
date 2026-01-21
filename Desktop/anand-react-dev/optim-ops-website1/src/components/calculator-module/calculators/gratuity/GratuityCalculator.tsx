import { useState } from "react";
import { Calculator, Calendar, AlertCircle, CheckCircle2 } from "lucide-react";

type ContractType = "Limited" | "Unlimited" | "";
type ExitReason = "Resignation" | "Termination" | "";

export default function GratuityCalculator() {
  const [salary, setSalary] = useState<string>("");
  const [startDate, setStartDate] = useState<string>("");
  const [endDate, setEndDate] = useState<string>("");
  const [contractType, setContractType] = useState<ContractType>("");
  const [exitReason, setExitReason] = useState<ExitReason>("");

  const [gratuity, setGratuity] = useState<number | null>(null);
  const [tenureText, setTenureText] = useState<string>("");
  const [errors, setErrors] = useState<{
    salary?: string;
    startDate?: string;
    endDate?: string;
    contractType?: string;
    exitReason?: string;
  }>({});

  const validateForm = () => {
    const newErrors: typeof errors = {};

    if (!salary || Number(salary) <= 0) {
      newErrors.salary = "Valid salary is required";
    }

    if (!startDate) {
      newErrors.startDate = "Start date is required";
    }

    if (!endDate) {
      newErrors.endDate = "End date is required";
    }

    if (startDate && endDate && new Date(startDate) >= new Date(endDate)) {
      newErrors.endDate = "End date must be after start date";
    }

    if (!contractType) {
      newErrors.contractType = "Contract type is required";
    }

    if (!exitReason) {
      newErrors.exitReason = "Exit reason is required";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const calculateTenure = () => {
    const start = new Date(startDate);
    const end = new Date(endDate);

    let days = Math.floor(
      (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24)
    );

    const years = Math.floor(days / 365);
    days %= 365;
    const months = Math.floor(days / 30);
    days %= 30;

    return { years, months, days };
  };

  const calculateGratuity = () => {
    if (!validateForm()) return;

    const salaryNum = Number(salary);
    const { years, months, days } = calculateTenure();
    const totalYears = years + months / 12 + days / 365;

    const dailyWage = salaryNum / 30;
    let gratuityAmount = 0;

    if (totalYears <= 5) {
      gratuityAmount = dailyWage * 21 * totalYears;
    } else {
      gratuityAmount = dailyWage * 21 * 5 + dailyWage * 30 * (totalYears - 5);
    }

    // Max cap = 2 years basic salary
    const maxGratuity = salaryNum * 24;
    gratuityAmount = Math.min(gratuityAmount, maxGratuity);

    setTenureText(`${years} years, ${months} months, ${days} days`);
    setGratuity(gratuityAmount);
  };

  const formatNumber = (num: number) => {
    return num.toLocaleString("en-AE", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 flex items-center justify-center p-4">
      <div className="w-full max-w-lg">
        {/* HEADER */}
        <div className="text-center bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 mb-4 p-4 rounded-xl">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Calculator className="w-7 h-7 text-white" />
            <h1 className="text-3xl font-bold text-white">
              Gratuity Calculator
            </h1>
          </div>
          <p className="text-white text-sm">
            Calculate your end-of-service gratuity amount (UAE Labor Law)
          </p>
        </div>

        {/* CARD */}
        <div className="bg-white rounded-xl shadow-xl p-6 space-y-5">
          {/* SALARY */}
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-2">
              Last Drawn Basic Salary <span className="text-red-500">*</span>
            </label>
            <div className="relative">
              <input
                type="number"
                placeholder="Enter your basic salary"
                value={salary}
                onChange={(e) => {
                  setSalary(e.target.value);
                  setErrors({ ...errors, salary: undefined });
                }}
                className={`w-full pl-4 pr-16 py-2 border-2 rounded-lg focus:ring-2 focus:ring-red-200 transition-all ${
                  errors.salary ? "border-red-500" : "border-gray-200 focus:border-red-500"
                }`}
              />
              <span className="absolute right-3 top-1/2 -translate-y-1/2 bg-gray-100 px-3 py-1 rounded text-sm font-medium text-gray-700">
                AED
              </span>
            </div>
            {errors.salary && (
              <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                <AlertCircle size={12} />
                <span>{errors.salary}</span>
              </div>
            )}
          </div>

          {/* DATES */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                First Working Day <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="date"
                  value={startDate}
                  onChange={(e) => {
                    setStartDate(e.target.value);
                    setErrors({ ...errors, startDate: undefined });
                  }}
                  className={`w-full pl-10 pr-3 py-2 border-2 rounded-lg focus:ring-2 focus:ring-red-200 transition-all ${
                    errors.startDate ? "border-red-500" : "border-gray-200 focus:border-red-500"
                  }`}
                />
              </div>
              {errors.startDate && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.startDate}</span>
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Last Working Day <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="date"
                  value={endDate}
                  onChange={(e) => {
                    setEndDate(e.target.value);
                    setErrors({ ...errors, endDate: undefined });
                  }}
                  className={`w-full pl-10 pr-3 py-2 border-2 rounded-lg focus:ring-2 focus:ring-red-200 transition-all ${
                    errors.endDate ? "border-red-500" : "border-gray-200 focus:border-red-500"
                  }`}
                />
              </div>
              {errors.endDate && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.endDate}</span>
                </div>
              )}
            </div>
          </div>

          {/* CONTRACT & EXIT */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Contract Type <span className="text-blue-500">*</span>
              </label>
              <select
                value={contractType}
                onChange={(e) => {
                  setContractType(e.target.value as ContractType);
                  setErrors({ ...errors, contractType: undefined });
                }}
                className={`w-full px-3 py-2 border-2 rounded-lg focus:ring-2 focus:ring-red-200 bg-white transition-all ${
                  errors.contractType ? "border-blue-500" : "border-gray-200 focus:border-blue-500"
                }`}
              >
                <option value="">Select contract</option>
                <option value="Limited">Limited</option>
                <option value="Unlimited">Unlimited</option>
              </select>
              {errors.contractType && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.contractType}</span>
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Exit Reason <span className="text-red-500">*</span>
              </label>
              <select
                value={exitReason}
                onChange={(e) => {
                  setExitReason(e.target.value as ExitReason);
                  setErrors({ ...errors, exitReason: undefined });
                }}
                className={`w-full px-3 py-2 border-2 rounded-lg focus:ring-2 focus:ring-red-200 bg-white transition-all ${
                  errors.exitReason ? "border-blue-500" : "border-gray-200 focus:border-blue-500"
                }`}
              >
                <option value="">Select reason</option>
                <option value="Resignation">Resignation</option>
                <option value="Termination">Termination</option>
              </select>
              {errors.exitReason && (
                <div className="flex items-center gap-1 mt-1.5 text-red-600 text-xs">
                  <AlertCircle size={12} />
                  <span>{errors.exitReason}</span>
                </div>
              )}
            </div>
          </div>

          {/* BUTTON */}
          <button
            onClick={calculateGratuity}
            className="w-full bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 hover:from-blue-600 hover:to-blue-600 text-white py-3 rounded-lg font-semibold shadow-lg transition-all transform hover:scale-[1.02] flex items-center justify-center gap-2"
          >
            <Calculator className="w-4 h-4" />
            Calculate Gratuity
          </button>

          {/* RESULT */}
          {gratuity !== null && (
            <div className="mt-1 pt-2 border-t-2 border-gray-200">
              <div className="bg-gradient-to-br from-green-50 to-emerald-50 rounded-xl p-5 border-2 border-green-200">
                <div className="flex items-center gap-2 mb-1">
                  <CheckCircle2 className="w-3 h-3 text-green-600" />
                  <p className="text-sm font-semibold text-gray-700">
                    Your Gratuity Amount
                  </p>
                </div>
                <p className="text-2xl font-bold text-green-700 mb-3">
                  AED {formatNumber(gratuity)}
                </p>
                <div className="bg-white/60 rounded-lg p-1 text-sm">
                  <p className="text-gray-700">
                    <span className="font-semibold">Tenure:</span> {tenureText}
                  </p>
                  <p className="text-gray-600 text-xs mt-1">
                    * Calculated as per UAE Labor Law
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* INFO NOTE */}
        <div className="mt-4 bg-blue-50 border border-blue-200 rounded-lg p-3">
          <p className="text-xs text-blue-800 flex items-start gap-2">
            <AlertCircle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
            <span>
              Gratuity is calculated based on 21 days salary for the first 5 years and 30 days for each subsequent year, capped at 2 years total salary.
            </span>
          </p>
        </div>
      </div>
    </div>
  );
}