import { useMemo, useState } from "react";
import { Calculator, Info, TrendingUp } from "lucide-react";

const GST_RATES = [0, 5, 12, 18, 28];

const GstCalculator = () => {
  const [amount, setAmount] = useState<number>(0);
  const [gstRate, setGstRate] = useState<number>(0);
  const [taxType, setTaxType] = useState<"exclusive" | "inclusive">("exclusive");

  const { actualAmount, gstAmount, totalAmount } = useMemo(() => {
    if (!amount || gstRate === 0) {
      return { actualAmount: amount, gstAmount: 0, totalAmount: amount };
    }

    if (taxType === "exclusive") {
      const gst = (amount * gstRate) / 100;
      return {
        actualAmount: amount,
        gstAmount: gst,
        totalAmount: amount + gst,
      };
    } else {
      const base = amount / (1 + gstRate / 100);
      const gst = amount - base;
      return {
        actualAmount: base,
        gstAmount: gst,
        totalAmount: amount,
      };
    }
  }, [amount, gstRate, taxType]);

  const formatCurrency = (value: number) =>
    `₹${value.toLocaleString("en-IN", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })}`;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
    

      <div className="relative z-10 max-w-4xl mx-auto px-4 py-8 sm:py-12 lg:py-16">
        {/* Header */}
        <div className="text-center  sm:mb-5">
          <h1 className="text-3xl sm:text-4xl lg:text-4xl font-bold bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 bg-clip-text text-transparent mb-3 leading-tight">
            GST Calculator
          </h1>
          <p className="text-sm sm:text-base text-slate-600 max-w-2xl mx-auto">
            Calculate GST with precision and confidence. Built for professionals, designed for everyone.
          </p>
        </div>
        {/* Main Calculator Card */}
        <div className="bg-white/80 backdrop-blur-xl rounded-1xl shadow-1xl border border-white/20 overflow-hidden mb-8">
          {/* Card Header */}
          <div className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700px-6 p-3 rounded-xl">
            <h2 className="text-lg sm:text-xl font-semibold text-white flex items-center gap-2">
              <Calculator className="w-5 h-5" />
              Calculate GST
            </h2>
          </div>

          <div className="p-2 sm:p-4">
            {/* Input Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6 mb-6">
              {/* Amount */}
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-2">Amount (₹)</label>
                <div className="relative">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 text-lg font-semibold">₹</span>
                  <input
                    type="number"
                    value={amount || ""}
                    onChange={(e) => setAmount(Number(e.target.value))}
                    placeholder="0.00"
                    className="w-full border-2 border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all hover:border-slate-300"
                  />
                </div>
              </div>

              {/* GST Rate */}
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-2">GST Rate</label>
                <select
                  value={gstRate}
                  onChange={(e) => setGstRate(Number(e.target.value))}
                  className="w-full border-2 border-slate-200 rounded-xl px-2 py-2 text-base font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all appearance-none bg-white cursor-pointer hover:border-slate-300"
                  style={{
                    backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%236b7280'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'%3E%3C/path%3E%3C/svg%3E")`,
                    backgroundRepeat: "no-repeat",
                    backgroundPosition: "right 0.75rem center",
                    backgroundSize: "1.5em 1.5em",
                    paddingRight: "2.5rem",
                  }}
                >
                  {GST_RATES.map((rate) => (
                    <option key={rate} value={rate}>{rate}%</option>
                  ))}
                </select>
              </div>

              {/* Tax Type */}
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-2">Tax Type</label>
                <select
                  value={taxType}
                  onChange={(e) => setTaxType(e.target.value as any)}
                  className="w-full border-2 border-slate-200 rounded-xl px-4 py-2 text-base font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all appearance-none bg-white cursor-pointer hover:border-slate-300"
                  style={{
                    backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%236b7280'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'%3E%3C/path%3E%3C/svg%3E")`,
                    backgroundRepeat: "no-repeat",
                    backgroundPosition: "right 0.75rem center",
                    backgroundSize: "1.5em 1.5em",
                    paddingRight: "2.5rem",
                  }}
                >
                  <option value="exclusive">Exclusive</option>
                  <option value="inclusive">Inclusive</option>
                </select>
              </div>
            </div>

            {/* Results Display */}
            <div className="bg-gradient-to-br from-slate-50 to-blue-50 rounded-xl p-4 border border-blue-100">
              {/* Desktop */}
              <div className="hidden sm:grid grid-cols-5 gap-4 items-center mb-4">
                <div className="col-span-2 bg-white rounded-xl p-2 text-center shadow-md">
                  <p className="text-xs font-semibold text-blue-600 mb-1">Base Amount</p>
                  <p className="text-xl font-bold text-slate-900">{formatCurrency(actualAmount)}</p>
                </div>
                <div className="flex justify-center">
                  <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold">+</div>
                </div>
                <div className="col-span-2 bg-white rounded-xl p-2 text-center shadow-md">
                  <p className="text-xs font-semibold text-green-600 mb-1">GST ({gstRate}%)</p>
                  <p className="text-xl font-bold text-slate-900">{formatCurrency(gstAmount)}</p>
                </div>
              </div>

              <div className="hidden sm:flex justify-center">
                <div className="w-2/3 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-xl p-2 text-center shadow-lg">
                  <p className="text-xs font-semibold text-blue-100 mb-1">Total Amount Payable</p>
                  <p className="text-2xl font-bold text-white">{formatCurrency(totalAmount)}</p>
                </div>
              </div>

              {/* Mobile */}
              <div className="sm:hidden space-y-3">
                <div className="bg-white rounded-xl p-3 shadow">
                  <p className="text-xs text-blue-600 font-semibold">Base Amount</p>
                  <p className="text-lg font-bold">{formatCurrency(actualAmount)}</p>
                </div>
                <div className="bg-white rounded-xl p-3 shadow">
                  <p className="text-xs text-green-600 font-semibold">GST ({gstRate}%)</p>
                  <p className="text-lg font-bold">{formatCurrency(gstAmount)}</p>
                </div>
                <div className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-xl p-4 shadow-lg">
                  <p className="text-xs text-blue-100 font-semibold">Total</p>
                  <p className="text-2xl font-bold text-white">{formatCurrency(totalAmount)}</p>
                </div>
              </div>
            </div>

            {/* Info */}
            <div className="mt-4 flex items-start gap-3 bg-blue-50 border border-blue-200 rounded-xl p-2">
              <Info className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-slate-700">
                <strong className="text-blue-600">{taxType === "exclusive" ? "Tax Exclusive" : "Tax Inclusive"}:</strong>{" "}
                {taxType === "exclusive" ? "GST will be added to the base amount." : "GST is already included in the entered amount."}
              </p>
            </div>
          </div>
        </div>

        {/* About GST */}
        <div className="bg-white/80 backdrop-blur-xl rounded-2xl shadow-xl border border-white/20 p-3 sm:p-4 mb-4">
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 mb-4">What is GST?</h2>
          <p className="text-sm sm:text-base text-slate-700 leading-relaxed">
            GST (Goods and Services Tax) is an indirect tax introduced in India on July 1, 2017. It replaced multiple cascading taxes levied by the central and state governments, creating a unified tax structure across the country for goods and services.
          </p>
        </div>

        {/* How to Calculate */}
        <div className="bg-white/80 backdrop-blur-xl rounded-2xl shadow-xl border border-white/20 p-3 sm:p-4 mb-4">
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 mb-6">How to Calculate GST</h2>
          <div className="space-y-6">
            <div className="flex gap-4">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white flex items-center justify-center font-bold">1</div>
              </div>
              <div>
                <h3 className="font-bold text-slate-900 mb-1">Enter the Amount</h3>
                <p className="text-sm text-slate-600">Input the base price of goods or services in the amount field.</p>
              </div>
            </div>
            <div className="flex gap-4">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white flex items-center justify-center font-bold">2</div>
              </div>
              <div>
                <h3 className="font-bold text-slate-900 mb-1">Select GST Rate</h3>
                <p className="text-sm text-slate-600">Choose the applicable GST rate from the dropdown (0%, 5%, 12%, 18%, or 28%).</p>
              </div>
            </div>
            <div className="flex gap-4">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white flex items-center justify-center font-bold">3</div>
              </div>
              <div>
                <h3 className="font-bold text-slate-900 mb-1">Choose Tax Type</h3>
                <p className="text-sm text-slate-600">Select whether the amount is tax inclusive or exclusive. The calculator will automatically compute the GST amount and total payable amount.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Types of GST */}
        <div className="bg-white/80 backdrop-blur-xl rounded-2xl shadow-xl border border-white/20 p-3 sm:p-4 mb-4">
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 mb-6">Types of GST in India</h2>
          <div className="space-y-4">
            <div className="border-l-4 border-blue-600 pl-4 py-2">
              <h3 className="font-bold text-slate-900 mb-1">CGST - Central GST</h3>
              <p className="text-sm text-slate-600">Collected by the central government on intra-state supply. Charged along with SGST for transactions within the same state.</p>
            </div>
            <div className="border-l-4 border-indigo-600 pl-4 py-2">
              <h3 className="font-bold text-slate-900 mb-1">SGST - State GST</h3>
              <p className="text-sm text-slate-600">Collected by state governments on intra-state supply. Governed by the SGST Act and usually equal to CGST rate.</p>
            </div>
            <div className="border-l-4 border-purple-600 pl-4 py-2">
              <h3 className="font-bold text-slate-900 mb-1">IGST - Integrated GST</h3>
              <p className="text-sm text-slate-600">Collected by the central government on inter-state transactions and imports. Replaces both CGST and SGST.</p>
            </div>
            <div className="border-l-4 border-pink-600 pl-4 py-2">
              <h3 className="font-bold text-slate-900 mb-1">UTGST - Union Territory GST</h3>
              <p className="text-sm text-slate-600">Applicable in union territories without legislature. Collected along with CGST, similar to SGST structure.</p>
            </div>
          </div>
        </div>

        {/* Benefits */}
        <div className="bg-gradient-to-br from-blue-600 to-indigo-600 rounded-2xl p-3 sm:p-2 shadow-1xl mb-2">
          <div className="flex items-center gap-3 mb-4">
            <TrendingUp className="w-6 h-6 text-white" />
            <h2 className="text-xl sm:text-2xl font-bold text-white">Why Use This Calculator?</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {[
              "Instant and accurate GST calculations",
              "Supports all GST rates and tax types",
              "Professional-grade precision",
              "Perfect for businesses and individuals",
              "Mobile-friendly and responsive",
              "Free to use, no registration needed",
            ].map((benefit, idx) => (
              <div key={idx} className="flex items-start gap-3 text-white">
                <div className="w-2 h-2 rounded-full bg-blue-200 mt-2 flex-shrink-0"></div>
                <p className="text-sm">{benefit}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="text-center">
          <p className="text-xs sm:text-sm text-slate-500">
            This GST calculator provides estimates based on current tax slabs. Please consult with a tax professional for official calculations and compliance.
          </p>
        </div>
      </div>

      <style>{`
        @keyframes blob {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(30px, -50px) scale(1.1); }
          66% { transform: translate(-20px, 20px) scale(0.9); }
        }
        .animate-blob { animation: blob 7s infinite; }
        .animation-delay-2000 { animation-delay: 2s; }
        .animation-delay-4000 { animation-delay: 4s; }
      `}</style>
    </div>
  );
};

export default GstCalculator;