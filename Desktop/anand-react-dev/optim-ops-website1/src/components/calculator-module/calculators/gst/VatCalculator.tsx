

import { useMemo, useState } from "react";
import { Calculator, Plus, Minus, Info } from "lucide-react";

type Mode = "add" | "remove";
type Currency = "₹" | "$" | "£" | "€";
type TaxSystem = "VAT" | "GST" | "Sales Tax";
type GstType = "CGST_SGST" | "IGST";

export default function VatCalculator() {
  const [amount, setAmount] = useState<number>(0);
  const [rate, setRate] = useState<number>(0);
  const [mode, setMode] = useState<Mode>("add");
  const [currency, setCurrency] = useState<Currency>("₹");
  const [taxSystem, setTaxSystem] = useState<TaxSystem>("VAT");
  const [gstType, setGstType] = useState<GstType>("CGST_SGST");

  const result = useMemo(() => {
    if (amount <= 0 || rate <= 0) {
      return {
        tax: 0,
        total: 0,
        base: 0,
        cgst: 0,
        sgst: 0,
        igst: 0,
      };
    }

    if (mode === "add") {
      const tax = (amount * rate) / 100;
      return {
        tax,
        total: amount + tax,
        base: amount,
        cgst: tax / 2,
        sgst: tax / 2,
        igst: tax,
      };
    } else {
      const base = amount / (1 + rate / 100);
      const tax = amount - base;
      return {
        tax,
        total: amount,
        base,
        cgst: tax / 2,
        sgst: tax / 2,
        igst: tax,
      };
    }
  }, [amount, rate, mode]);

  const formatNumber = (num: number) => {
    return num.toLocaleString("en-IN", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 flex items-center justify-center p-4">
      <div className="max-w-2xl w-full bg-white rounded-xl shadow-2xl overflow-hidden">
        
        {/* HEADER */}
        <div className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 p-6">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Calculator className="w-6 h-6 text-white" />
            <h1 className="text-2xl  text-white font-bold">Tax Calculator</h1>
          </div>
          <p className="text-center text-white text-sm">
            Calculate {taxSystem} instantly with live results
          </p>
        </div>

        <div className="p-6">
          {/* MODE TOGGLE */}
          <div className="flex gap-2 mb-6">
            <button
              onClick={() => setMode("add")}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg font-medium transition-all ${
                mode === "add"
                  ? "bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white shadow-md"
                  : "bg-gray-100 text-gray-700 hover:bg-gray-200"
              }`}
            >
              <Plus className="w-4 h-4" />
              Add Tax
            </button>
            <button
              onClick={() => setMode("remove")}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg font-medium transition-all ${
                mode === "remove"
                  ? "bg-gradient-to-br from-red-600 via-purple-400 to-indigo-400 text-white shadow-md"
                  : "bg-gray-100 text-gray-700 hover:bg-gray-200"
              }`}
            >
              <Minus className="w-4 h-4" />
              Remove Tax
            </button>
          </div>

          {/* INPUT SECTION */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Amount
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 font-medium">
                  {currency}
                </span>
                <input
                  type="number"
                  value={amount}
                  onChange={(e) => setAmount(Number(e.target.value))}
                  className="w-full pl-10 pr-4 py-2.5 border-2 border-gray-200 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all"
                  placeholder="0.00"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Tax Rate
              </label>
              <div className="relative">
                <input
                  type="number"
                  value={rate}
                  onChange={(e) => setRate(Number(e.target.value))}
                  className="w-full pr-10 pl-4 py-2.5 border-2 border-gray-200 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all"
                  placeholder="0"
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 font-medium">
                  %
                </span>
              </div>
            </div>
          </div>

          {/* QUICK RATES */}
          <div className="flex flex-wrap gap-2 mb-6">
            <span className="text-xs font-medium text-gray-500 flex items-center mr-2">
              Quick rates:
            </span>
            {[5, 12, 18, 28].map((r) => (
              <button
                key={r}
                onClick={() => setRate(r)}
                className={`px-3 py-1 text-xs font-medium rounded-md transition-all ${
                  rate === r
                    ? "bg-blue-600 text-white"
                    : "bg-gray-100 hover:bg-gray-200 text-gray-700"
                }`}
              >
                {r}%
              </button>
            ))}
          </div>

          {/* SETTINGS ROW */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
            {/* Currency Dropdown */}
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">
                Currency
              </label>
              <select
                value={currency}
                onChange={(e) => setCurrency(e.target.value as Currency)}
                className="w-full px-3 py-2 border-2 border-gray-200 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 text-sm bg-white transition-all"
              >
                <option value="₹">₹ INR</option>
                <option value="$">$ USD</option>
                <option value="£">£ GBP</option>
                <option value="€">€ EUR</option>
              </select>
            </div>

            {/* Tax System Dropdown */}
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">
                Tax System
              </label>
              <select
                value={taxSystem}
                onChange={(e) => setTaxSystem(e.target.value as TaxSystem)}
                className="w-full px-3 py-2 border-2 border-gray-200 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 text-sm bg-white transition-all"
              >
                <option value="GST">GST (India)</option>
                <option value="VAT">VAT</option>
                <option value="Sales Tax">Sales Tax</option>
              </select>
            </div>

            {/* GST Type Dropdown */}
            {taxSystem === "GST" && (
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1.5">
                  GST Type
                </label>
                <select
                  value={gstType}
                  onChange={(e) => setGstType(e.target.value as GstType)}
                  className="w-full px-3 py-2 border-2 border-gray-200 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 text-sm bg-white transition-all"
                >
                  <option value="CGST_SGST">CGST + SGST</option>
                  <option value="IGST">IGST</option>
                </select>
              </div>
            )}
          </div>

          {/* RESULTS */}
          <div className="bg-gradient-to-br from-slate-50 to-blue-50 rounded-xl p-5 border-2 border-blue-100">
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div className="text-center">
                <p className="text-xs text-gray-600 mb-1 font-medium">Base</p>
                <p className="text-lg font-bold text-gray-800">
                  {currency}{formatNumber(result.base)}
                </p>
              </div>
              
              <div className="text-center border-l-2 border-r-2 border-blue-200">
                <p className="text-xs text-gray-600 mb-1 font-medium">Tax</p>
                <p className="text-lg font-bold text-blue-600">
                  {currency}{formatNumber(result.tax)}
                </p>
              </div>
              
              <div className="text-center">
                <p className="text-xs text-gray-600 mb-1 font-medium">Total</p>
                <p className="text-lg font-bold text-green-600">
                  {currency}{formatNumber(result.total)}
                </p>
              </div>
            </div>

            {/* GST BREAKDOWN */}
            {taxSystem === "GST" && result.tax > 0 && (
              <div className="pt-4 border-t-2 border-blue-200">
                <div className="flex items-center gap-2 mb-2">
                  <Info className="w-3 h-3 text-blue-600" />
                  <p className="text-xs font-semibold text-gray-700">Tax Breakdown</p>
                </div>
                
                {gstType === "CGST_SGST" ? (
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div className="bg-white rounded-lg p-2.5 border border-blue-100">
                      <p className="text-gray-600 mb-0.5">CGST ({rate / 2}%)</p>
                      <p className="font-bold text-gray-800">
                        {currency}{formatNumber(result.cgst)}
                      </p>
                    </div>
                    <div className="bg-white rounded-lg p-2.5 border border-blue-100">
                      <p className="text-gray-600 mb-0.5">SGST ({rate / 2}%)</p>
                      <p className="font-bold text-gray-800">
                        {currency}{formatNumber(result.sgst)}
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="bg-white rounded-lg p-2.5 border border-blue-100 text-xs">
                    <p className="text-gray-600 mb-0.5">IGST ({rate}%)</p>
                    <p className="font-bold text-gray-800">
                      {currency}{formatNumber(result.igst)}
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* FORMULA INFO */}
          <div className="mt-4 p-3 bg-amber-50 border border-amber-200 rounded-lg">
            <p className="text-xs text-amber-800 flex items-start gap-2">
              <Info className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
              <span>
                {mode === "add" 
                  ? `Adding ${rate}% tax to base amount of ${currency}${formatNumber(amount)}`
                  : `Removing ${rate}% tax from total amount of ${currency}${formatNumber(amount)}`
                }
              </span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
