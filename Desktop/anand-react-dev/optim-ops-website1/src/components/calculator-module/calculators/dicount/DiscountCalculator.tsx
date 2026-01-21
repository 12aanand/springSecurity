
import { useMemo, useState } from "react";
import {
  Calculator,
  Info,
  TrendingDown,
  CheckCircle,
  Sparkles,
  DollarSign,
  Percent,
  Zap,
} from "lucide-react";

/* -------------------- TYPES -------------------- */
type Mode = "simple" | "item";
type DiscountType = "%" | "₹";

type Item = {
  name: string;
  amount: number;
  tax: number;
  discountValue: number;
  discountType: DiscountType;
};

/* -------------------- HELPERS -------------------- */
const format = (n: number) =>
  `₹${Math.abs(n).toLocaleString("en-IN", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;

/* -------------------- COMPONENT -------------------- */
const DiscountCalculator = () => {
  const [mode, setMode] = useState<Mode>("simple");
  const [applyTaxAfter, setApplyTaxAfter] = useState(true);

  /* -------- SIMPLE STATE -------- */
  const [amount, setAmount] = useState(100);
  const [tax, setTax] = useState(10);
  const [discountValue, setDiscountValue] = useState(10);
  const [discountType, setDiscountType] = useState<DiscountType>("₹");

  /* -------- ITEM STATE -------- */
  const [items, setItems] = useState<Item[]>([
    { name: "", amount: 0, tax: 0, discountValue: 0, discountType: "%" },
  ]);

  /* -------------------- SIMPLE CALCULATION -------------------- */
  const simpleResult = useMemo(() => {
    const discountAmount =
      discountType === "%" ? (amount * discountValue) / 100 : discountValue;

    const afterDiscount = amount - discountAmount;
    const taxBase = applyTaxAfter ? afterDiscount : amount;
    const taxAmount = (taxBase * tax) / 100;
    const finalAmount = afterDiscount + taxAmount;

    return {
      finalAmount,
      difference: amount - finalAmount,
    };
  }, [amount, tax, discountValue, discountType, applyTaxAfter]);

  /* -------------------- ITEM CALCULATION -------------------- */
  const itemSummary = useMemo(() => {
    let original = 0;
    let final = 0;

    items.forEach((item) => {
      const discountAmount =
        item.discountType === "%"
          ? (item.amount * item.discountValue) / 100
          : item.discountValue;

      const afterDiscount = item.amount - discountAmount;
      const taxBase = applyTaxAfter ? afterDiscount : item.amount;
      const taxAmount = (taxBase * item.tax) / 100;

      original += item.amount;
      final += afterDiscount + taxAmount;
    });

    return {
      original,
      final,
      difference: original - final,
    };
  }, [items, applyTaxAfter]);

  /* -------------------- UI -------------------- */
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-white px-4 py-6 md:py-8 relative overflow-hidden">
      {/* Subtle Gradient Orbs */}
      <div className="absolute top-0 left-1/4 w-64 h-64 bg-blue-200 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse"></div>
      <div className="absolute bottom-0 right-1/4 w-64 h-64 bg-cyan-200 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse animation-delay-2000"></div>
      
      <div className="relative z-10 max-w-4xl mx-auto">
        {/* Header - Made Smaller */}
        <div className="text-center mb-6 md:mb-8">
          <div className="inline-flex items-center gap-1.5 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white px-3 py-1.5 rounded-full text-xs font-bold mb-4 shadow-sm">
            <Sparkles className="w-3 h-3" />
            <span>SMART CALCULATOR</span>
          </div>
          <h1 className="text-2xl md:text-3xl font-bold mb-2 text-gray-900">
            Discount Calculator
          </h1>
          <p className="text-sm text-gray-600 max-w-md mx-auto">
            Calculate discounts instantly with precision for businesses and individuals.
          </p>
        </div>

        {/* Main Card - Compact */}
        <div className="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden mb-8">
          {/* Tabs - Smaller */}
          <div className="border-b border-gray-200 px-4 md:px-6 py-4 bg-gradient-to-r from-blue-50 to-cyan-50">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div className="inline-flex bg-white rounded-lg p-1 shadow-sm">
                {["simple", "item"].map((m) => (
                  <button
                    key={m}
                    onClick={() => setMode(m as Mode)}
                    className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${
                      mode === m
                        ? "bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white shadow-sm"
                        : "text-gray-600 hover:text-gray-900"
                    }`}
                  >
                    {m === "simple" ? "Simple Mode" : "Multi-Item"}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-2 bg-white rounded-lg px-3 py-1.5 shadow-sm">
                <span className="text-xs font-semibold text-gray-700">Tax After Discount</span>
                <button
                  onClick={() => setApplyTaxAfter(!applyTaxAfter)}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                    applyTaxAfter ? "bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700" : "bg-gray-300"
                  }`}
                >
                  <span
                    className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-sm transition-transform ${
                      applyTaxAfter ? "translate-x-5" : "translate-x-0.5"
                    }`}
                  />
                </button>
              </div>
            </div>
          </div>

          <div className="p-4 md:p-6">
            {/* ---------------- SIMPLE MODE ---------------- */}
            {mode === "simple" && (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                  {/* Amount */}
                  <div>
                    <label className="block text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1">
                      <DollarSign className="w-3 h-3 text-blue-600" />
                      Amount
                    </label>
                    <input
                      type="number"
                      value={amount}
                      onChange={(e) => setAmount(Number(e.target.value))}
                      placeholder="Enter amount"
                      className="w-full bg-gray-50 border border-blue-200 rounded-lg px-3 py-2 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-blue-300 focus:border-blue-400 transition-all placeholder:text-gray-400"
                    />
                  </div>

                  {/* Tax */}
                  <div>
                    <label className="block text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1">
                      <Percent className="w-3 h-3 text-blue-600" />
                      Tax Percentage
                    </label>
                    <input
                      type="number"
                      value={tax}
                      onChange={(e) => setTax(Number(e.target.value))}
                      placeholder="Tax %"
                      className="w-full bg-gray-50 border border-blue-200 rounded-lg px-3 py-2 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-blue-300 focus:border-blue-400 transition-all placeholder:text-gray-400"
                    />
                  </div>

                  {/* Discount */}
                  <div>
                    <label className="block text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1">
                      <TrendingDown className="w-3 h-3 text-blue-600" />
                      Discount
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="number"
                        value={discountValue}
                        onChange={(e) => setDiscountValue(Number(e.target.value))}
                        placeholder="0"
                        className="flex-1 bg-gray-50 border border-blue-200 rounded-lg px-3 py-2 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-blue-300 focus:border-blue-400 transition-all placeholder:text-gray-400"
                      />
                      <select
                        value={discountType}
                        onChange={(e) => setDiscountType(e.target.value as DiscountType)}
                        className="bg-violet-400 text-white rounded-lg px-2 text-xs font-semibold cursor-pointer"
                      >
                        <option value="₹">₹</option>
                        <option value="%">%</option>
                      </select>
                    </div>
                  </div>
                </div>

                {/* Results - Compact */}
                <div className="bg-gradient-to-r from-blue-50 to-cyan-50 rounded-lg p-4 border border-blue-100">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
                    <div className="bg-white rounded-lg p-3 text-center shadow-sm">
                      <p className="text-xs font-semibold text-blue-600 mb-1">ORIGINAL</p>
                      <p className="text-lg font-bold text-gray-900">{format(amount)}</p>
                    </div>

                    <div className="bg-white rounded-lg p-3 text-center shadow-sm">
                      <p className="text-xs font-semibold text-gray-600 mb-1">FINAL</p>
                      <p className="text-lg font-bold text-gray-900">{format(simpleResult.finalAmount)}</p>
                    </div>

                    <div className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-lg p-3 text-center shadow-sm">
                      <p className="text-xs font-semibold text-white/90 mb-1">YOU SAVE</p>
                      <p className="text-lg font-bold text-white">{format(simpleResult.difference)}</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-center gap-2 text-xs font-semibold text-blue-700 bg-white/50 rounded-lg p-2">
                    <Zap className="w-3 h-3" />
                    <span>Instant calculation with 100% accuracy</span>
                  </div>
                </div>
              </>
            )}

            {/* ---------------- ITEM MODE ---------------- */}
            {mode === "item" && (
              <>
                {/* Table Header - Compact */}
                <div className="hidden sm:grid grid-cols-12 text-xs font-semibold text-blue-700 bg-gradient-to-r from-blue-50 to-cyan-50 py-2 px-3 rounded-lg mb-3">
                  <div className="col-span-3">ITEM NAME</div>
                  <div className="col-span-2">AMOUNT</div>
                  <div className="col-span-2">TAX %</div>
                  <div className="col-span-3">DISCOUNT</div>
                  <div className="col-span-2">FINAL</div>
                </div>

                {/* Rows - Compact */}
                <div className="space-y-3">
                  {items.map((item, idx) => {
                    const discountAmount =
                      item.discountType === "%"
                        ? (item.amount * item.discountValue) / 100
                        : item.discountValue;

                    const afterDiscount = item.amount - discountAmount;
                    const taxBase = applyTaxAfter ? afterDiscount : item.amount;
                    const taxAmount = (taxBase * item.tax) / 100;
                    const finalAmount = afterDiscount + taxAmount;

                    return (
                      <div
                        key={idx}
                        className="sm:grid sm:grid-cols-12 sm:items-center gap-2 bg-white rounded-lg p-3 shadow-sm border border-blue-100 space-y-2 sm:space-y-0"
                      >
                        <div className="sm:col-span-3">
                          <label className="block sm:hidden text-xs font-semibold text-gray-700 mb-1">Item</label>
                          <input
                            placeholder="Item name"
                            value={item.name}
                            onChange={(e) =>
                              setItems((prev) =>
                                prev.map((it, i) =>
                                  i === idx ? { ...it, name: e.target.value } : it
                                )
                              )
                            }
                            className="w-full border border-blue-200 px-3 py-2 rounded-md text-sm font-medium focus:outline-none focus:ring-1 focus:ring-blue-300"
                          />
                        </div>

                        <div className="sm:col-span-2">
                          <label className="block sm:hidden text-xs font-semibold text-gray-700 mb-1">Amount</label>
                          <input
                            type="number"
                            placeholder="0"
                            value={item.amount}
                            onChange={(e) =>
                              setItems((prev) =>
                                prev.map((it, i) =>
                                  i === idx ? { ...it, amount: +e.target.value } : it
                                )
                              )
                            }
                            className="w-full border border-blue-200 px-3 py-2 rounded-md text-sm font-medium focus:outline-none focus:ring-1 focus:ring-blue-300"
                          />
                        </div>

                        <div className="sm:col-span-2">
                          <label className="block sm:hidden text-xs font-semibold text-gray-700 mb-1">Tax %</label>
                          <input
                            type="number"
                            placeholder="0"
                            value={item.tax}
                            onChange={(e) =>
                              setItems((prev) =>
                                prev.map((it, i) =>
                                  i === idx ? { ...it, tax: +e.target.value } : it
                                )
                              )
                            }
                            className="w-full border border-blue-200 px-3 py-2 rounded-md text-sm font-medium focus:outline-none focus:ring-1 focus:ring-blue-300"
                          />
                        </div>

                        <div className="sm:col-span-3">
                          <label className="block sm:hidden text-xs font-semibold text-gray-700 mb-1">Discount</label>
                          <div className="flex gap-2">
                            <input
                              type="number"
                              placeholder="0"
                              value={item.discountValue}
                              onChange={(e) =>
                                setItems((prev) =>
                                  prev.map((it, i) =>
                                    i === idx
                                      ? { ...it, discountValue: +e.target.value }
                                      : it
                                  )
                                )
                              }
                              className="w-full border border-blue-200 px-3 py-2 rounded-md text-sm font-medium focus:outline-none focus:ring-1 focus:ring-blue-300"
                            />
                            <select
                              value={item.discountType}
                              onChange={(e) =>
                                setItems((prev) =>
                                  prev.map((it, i) =>
                                    i === idx
                                      ? { ...it, discountType: e.target.value as DiscountType }
                                      : it
                                  )
                                )
                              }
                              className="bg-blue-600 text-white rounded-md px-2 text-xs font-semibold"
                            >
                              <option value="%">%</option>
                              <option value="₹">₹</option>
                            </select>
                          </div>
                        </div>

                        <div className="sm:col-span-2 flex items-center justify-between sm:justify-end gap-2">
                          <span className="text-xs font-semibold text-gray-700 sm:hidden">Final:</span>
                          <span className="font-bold text-sm text-blue-700">{format(finalAmount)}</span>
                          <button
                            onClick={() => setItems((prev) => prev.filter((_, i) => i !== idx))}
                            className="text-red-500 hover:text-red-700 font-bold text-lg"
                          >
                            ×
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Add Item Button */}
                <button
                  onClick={() =>
                    setItems([...items, { name: "", amount: 0, tax: 0, discountValue: 0, discountType: "%" }])
                  }
                  className="mt-4 flex items-center gap-1 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white px-4 py-2 rounded-lg text-sm font-semibold shadow-sm hover:shadow transition-all"
                >
                  <span className="text-lg">+</span> Add Another Item
                </button>

                {/* Summary - Compact */}
                <div className="mt-6 bg-gradient-to-r from-blue-50 to-cyan-50 rounded-lg p-4 border border-blue-100">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="bg-white rounded-lg p-3 text-center shadow-sm">
                      <p className="text-xs font-semibold text-blue-600 mb-1">TOTAL AMOUNT</p>
                      <p className="text-lg font-bold text-gray-900">{format(itemSummary.original)}</p>
                    </div>

                    <div className="bg-white rounded-lg p-3 text-center shadow-sm">
                      <p className="text-xs font-semibold text-gray-600 mb-1">AFTER DISCOUNT</p>
                      <p className="text-lg font-bold text-gray-900">{format(itemSummary.final)}</p>
                    </div>

                    <div className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-lg p-3 text-center shadow-sm">
                      <p className="text-xs font-semibold text-white/90 mb-1">TOTAL SAVINGS</p>
                      <p className="text-lg font-bold text-white">{format(itemSummary.difference)}</p>
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Info Cards - Compact */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          {/* What is */}
          <div className="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-lg flex items-center justify-center">
                <Info className="w-4 h-4 text-white" />
              </div>
              <h2 className="text-sm font-bold text-gray-900">What is this?</h2>
            </div>
            <p className="text-xs text-gray-600 leading-relaxed">
              A powerful discount calculator that helps you instantly calculate discounted prices with tax considerations.
            </p>
          </div>

          {/* How to Use */}
          <div className="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-lg flex items-center justify-center">
                <Calculator className="w-4 h-4 text-white" />
              </div>
              <h2 className="text-sm font-bold text-gray-900">How to use?</h2>
            </div>
            <p className="text-xs text-gray-600 leading-relaxed">
              Enter amount, set discount, add tax if needed, and see final price instantly.
            </p>
          </div>
        </div>

        {/* Features - Compact */}
        <div className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-lg p-4 shadow-sm mb-6">
          <h2 className="text-sm font-bold text-white mb-3 text-center">Why Choose This Calculator?</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {[
              "Fast calculations",
              "Multiple items",
              "Flexible tax timing",
              "Percentage or fixed",
              "Mobile optimized",
              "Free to use",
            ].map((feature, idx) => (
              <div key={idx} className="flex items-center gap-2 bg-white/20 backdrop-blur-sm rounded-md px-2 py-1.5">
                <CheckCircle className="w-3 h-3 text-white flex-shrink-0" />
                <p className="text-xs font-medium text-white">{feature}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="text-center">
          <p className="text-xs text-gray-500">
            Made for accurate discount calculations. Perfect for businesses and individuals.
          </p>
        </div>
      </div>

      <style>{`
        .animation-delay-2000 {
          animation-delay: 2s;
        }
      `}</style>
    </div>
  );
};

export default DiscountCalculator;
