

import { useState, useEffect } from "react";

/* -------------------- TYPES -------------------- */
type Slab = {
  from: number;
  to: number;
  rate: number;
};

type FY = "current" | "previous";

type BreakupItem = {
  label: string;
  rate: string;
  tax: number;
};

type AgeGroup = "less-than-60" | "60-80" | "above-80";

/* -------------------- OLD REGIME (AGE BASED – ALL FY) -------------------- */
const OLD_SLABS_BY_AGE: Record<AgeGroup, Slab[]> = {
  "less-than-60": [
    { from: 0, to: 250000, rate: 0 },
    { from: 250000, to: 500000, rate: 0.05 },
    { from: 500000, to: 1000000, rate: 0.2 },
    { from: 1000000, to: Infinity, rate: 0.3 },
  ],

  "60-80": [
    { from: 0, to: 300000, rate: 0 },
    { from: 300000, to: 500000, rate: 0.05 },
    { from: 500000, to: 1000000, rate: 0.2 },
    { from: 1000000, to: Infinity, rate: 0.3 },
  ],

  "above-80": [
    { from: 0, to: 500000, rate: 0 },
    { from: 500000, to: 1000000, rate: 0.2 },
    { from: 1000000, to: Infinity, rate: 0.3 },
  ],
};

/* -------------------- NEW REGIME : FY 2025–26 (SAME FOR ALL AGE) -------------------- */
const CURRENT_NEW_SLABS = [
  { from: 0, to: 400000, rate: 0 },
  { from: 400000, to: 800000, rate: 0.05 },
  { from: 800000, to: 1200000, rate: 0.1 },
  { from: 1200000, to: 1600000, rate: 0.15 },
  { from: 1600000, to: 2000000, rate: 0.2 },
  { from: 2000000, to: 2400000, rate: 0.25 },
  { from: 2400000, to: Infinity, rate: 0.3 },
];

/* -------------------- NEW REGIME : FY 2024–25 (AGE BASED) -------------------- */
const PREVIOUS_NEW_SLABS_BY_AGE: Record<AgeGroup, Slab[]> = {
  "less-than-60": [
    { from: 0, to: 300000, rate: 0 },
    { from: 300000, to: 700000, rate: 0.05 },
    { from: 700000, to: 1000000, rate: 0.1 },
    { from: 1000000, to: 1200000, rate: 0.15 },
    { from: 1200000, to: Infinity, rate: 0.2 },
  ],

  "60-80": [
    { from: 0, to: 300000, rate: 0 },
    { from: 300000, to: 700000, rate: 0.05 },
    { from: 700000, to: 1000000, rate: 0.1 },
    { from: 1000000, to: 1200000, rate: 0.15 },
    { from: 1200000, to: Infinity, rate: 0.2 },
  ],

  "above-80": [
    { from: 0, to: 300000, rate: 0 },
    { from: 300000, to: 700000, rate: 0.05 },
    { from: 700000, to: 1000000, rate: 0.1 },
    { from: 1000000, to: 1200000, rate: 0.15 },
    { from: 1200000, to: Infinity, rate: 0.2 },
  ],
};

const STANDARD_DEDUCTION = 75000;

/* -------------------- HELPERS -------------------- */
const formatCurrency = (n: number) =>
  `₹${Math.round(n).toLocaleString("en-IN")}`;

const calculateSlabTax = (
  income: number,
  slabs: Slab[]
): { totalTax: number; breakup: BreakupItem[] } => {
  let remaining = income;
  let totalTax = 0;
  const breakup: BreakupItem[] = [];

  for (const slab of slabs) {
    if (remaining <= 0) break;

    if (slab.to === Infinity) {
      const tax = remaining * slab.rate;
      breakup.push({
        label: `Above ${formatCurrency(slab.from + 1)}`,
        rate: `${slab.rate * 100}%`,
        tax,
      });
      totalTax += tax;
      break;
    }

    const taxable = Math.min(remaining, slab.to - slab.from);
    if (taxable > 0) {
      const tax = taxable * slab.rate;
      breakup.push({
        label: `${formatCurrency(slab.from + 1)} to ${formatCurrency(
          slab.from + taxable
        )}`,
        rate: `${slab.rate * 100}%`,
        tax,
      });
      totalTax += tax;
      remaining -= taxable;
    }
  }

  return { totalTax, breakup };
};

/* -------------------- COMPONENT -------------------- */
const IncomeTaxCalculator = () => {
  /* STATE */
  const [activeFY, setActiveFY] = useState<FY>("current");
  const [showResult, setShowResult] = useState(false);
  const [showBreakup, setShowBreakup] = useState<"old" | "new" | null>(null);
  const [age, setAge] = useState<AgeGroup>("less-than-60");

  /* INPUTS */
  const [salary, setSalary] = useState(1400000);

  const [showOtherIncome, setShowOtherIncome] = useState(false);

  const [interestFD, setInterestFD] = useState(0);
  const [rentalIncome, setRentalIncome] = useState(0);
  const [municipalTax, setMunicipalTax] = useState(0);
  const [letOutLoanInterest, setLetOutLoanInterest] = useState(0);
  const [otherMiscIncome, setOtherMiscIncome] = useState(0);

  /* EXEMPTIONS */
  const [hra, setHra] = useState(10000);
  const [housingLoan, setHousingLoan] = useState(10000);
  const [sec80C, set80C] = useState(9999);
  const [sec80CCD, set80CCD] = useState(10000);
  const [sec80CCD1B, set80CCD1B] = useState(0);
  const [sec80D, set80D] = useState(0);
  const [sec80E, set80E] = useState(0);
  const [sec80EEA, set80EEA] = useState(0);
  const [sec80EEB, set80EEB] = useState(0);
  const [sec80G, set80G] = useState(0);

  const netAnnualValue = Math.max(0, rentalIncome - municipalTax);

  const standardDeductionRental = netAnnualValue * 0.3;

  const taxableRentalIncome =
    netAnnualValue - standardDeductionRental - letOutLoanInterest;

  const housePropertyIncome = Math.max(taxableRentalIncome, -200000);

  const totalOtherIncome = interestFD + otherMiscIncome + housePropertyIncome;

  /* CALCULATIONS */
  const grossIncome = salary + totalOtherIncome;

  // const combined80C = Math.min(sec80C + sec80CCD, 150000);

  // const oldDeductions =
  //   hra +
  //   Math.min(housingLoan, 200000) +
  //   combined80C +                 // ✅ capped at 1,50,000
  //   Math.min(sec80CCD1B, 50000) +  // ✅ extra NPS
  //   sec80D +
  //   sec80E +
  //   Math.min(sec80EEA, 150000) +
  //   Math.min(sec80EEB, 150000) +
  //   sec80G;

  const oldDeductions = 150000;

  const oldTaxable = Math.max(0, grossIncome - oldDeductions);
  const newTaxable = Math.max(0, grossIncome - STANDARD_DEDUCTION);

  const getSlabs = (regime: "old" | "new") => {
    if (regime === "old") {
      return OLD_SLABS_BY_AGE[age];
    }

    if (activeFY === "current") {
      return CURRENT_NEW_SLABS;
    }

    return PREVIOUS_NEW_SLABS_BY_AGE[age];
  };

  const oldCalc = calculateSlabTax(oldTaxable, getSlabs("old"));
  const newCalc = calculateSlabTax(newTaxable, getSlabs("new"));

  /* Apply rebates */
  let oldTax = oldCalc.totalTax;
  let newTax = newCalc.totalTax;

  if (activeFY === "current") {
    // Current FY rebates
    if (oldTaxable <= 500000) oldTax = 0;
    if (newTaxable <= 1200000) newTax = Math.max(0, newTax - 60000);
  } else {
    // Previous FY rebates
    if (oldTaxable <= 500000) oldTax = 0;
    // No specific rebate for new regime in previous FY
  }

  const oldCess = oldTax * 0.04;
  const newCess = newTax * 0.04;
  const oldTotal = oldTax + oldCess;
  const newTotal = newTax + newCess;
  const saving = oldTotal - newTotal;

  return (

    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 p-2 md:p-4 lg:p-6">
      {/* HEADER - Made responsive */}
      <div className="text-center bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700  rounded-lg md:rounded-xl p-2 md:p-4 mb-4 md:mb-4">
        {/* TITLE */}
        <h1 className="text-3xl md:text-5xl lg:text-3xl font-semibold text-white">
          Income Tax Calculator
        </h1>
        <p className="text-xs md:text-sm text-white mt-1 md:mt-2 max-w-2xl mx-auto px-2">
          A comparative tool to calculate income tax under old and new tax regimes
        </p>

        {/* FY SWITCHER - Made responsive */}
        <div className="flex mt-2 flex-col md:flex-row items-center justify-center gap-3 md:gap-4 bg-white border rounded-lg md:rounded-md shadow-sm px-1 md:px-1 py-1 md:py-1 mx-auto max-w-lg">
          <span className="text-xs md:text-sm font-medium text-gray-800 whitespace-nowrap">
            Financial Year
          </span>

          <div className="flex items-center gap-1 md:gap-2">
            <button
              onClick={() => setActiveFY("previous")}
              className={`px-2 md:px-1 py-1 md:py-2 rounded text-xs md:text-sm font-medium transition whitespace-nowrap ${
                activeFY === "previous"
                  ? "bg-purple-600 text-white"
                  : "bg-gray-100 text-gray-700 hover:bg-gray-200"
              }`}
            >
              FY 2024–25
            </button>

            <button
              onClick={() => setActiveFY("current")}
              className={`px-2 md:px-3 py-1.5 md:py-2 rounded text-xs md:text-sm font-medium transition whitespace-nowrap ${
                activeFY === "current"
                  ? "bg-green-600 text-white"
                  : "bg-gray-100 text-gray-700 hover:bg-gray-200"
              }`}
            >
              FY 2025–26
            </button>
          </div>

          <span className="text-[10px] md:text-xs text-gray-800 whitespace-nowrap">
            {activeFY === "current"
              ? "Currently showing FY 2025–26"
              : "Currently showing FY 2024–25"}
          </span>
        </div>
      </div>

      {!showResult ? (
        /* INPUT FORM - Made responsive */
        <div className="max-w-3xl mx-auto bg-white rounded-lg md:rounded-xl shadow p-4 md:p-6 lg:p-8">
          {/* INCOME DETAILS */}
          <h2 className="text-indigo-600 font-semibold text-base md:text-lg mb-4">
            Yearly income from salary
          </h2>

          <div className="space-y-1 md:space-y-3">
            {/* Salary */}
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 md:gap-6">
              <label className="text-sm md:text-base text-gray-800 w-full md:w-1/2">
                Yearly income from salary
              </label>
              <input
                type="number"
                value={salary}
                onChange={(e) => setSalary(Number(e.target.value))}
                className="w-full md:w-44 px-3 py-2 md:py-1.5 text-sm border rounded"
              />
            </div>

            {/* Age */}
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 md:gap-6">
              <label className="text-sm md:text-base text-gray-800 w-full md:w-1/2">
                Age
              </label>
              <select
                value={age}
                onChange={(e) => setAge(e.target.value as AgeGroup)}
                className="w-full md:w-44 px-3 py-2 md:py-1 text-sm border rounded"
              >
                <option value="less-than-60">Less than 60</option>
                <option value="60-80">60 to 80</option>
                <option value="above-80">Above 80</option>
              </select>
            </div>

            {/* Other Income */}
            <div className="mt-4">
              <button
                type="button"
                onClick={() => setShowOtherIncome((prev) => !prev)}
                className="text-indigo-600 text-sm md:text-base font-medium flex items-center gap-1 hover:text-blue-800 transition-colors"
              >
                <span className="text-lg">{showOtherIncome ? "−" : "+"}</span>
                Income from other sources
                <span className="text-gray-500 text-xs md:text-sm hidden md:inline">
                  (Interest on FD and let-out property)
                </span>
              </button>
              <span className="text-gray-500 text-xs md:hidden block mt-1">
                (Interest on FD and let-out property)
              </span>
              
              {showOtherIncome && (
                <div className="mt-4 space-y-3 md:space-y-4 border-l-2 border-blue-200 pl-3 md:pl-4">
                  {/* Interest from FD */}
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 md:gap-4">
                    <label className="text-sm md:text-base text-gray-700 w-full md:w-1/2">
                      Interest from savings bank accounts / FD accounts
                    </label>
                    <input
                      type="number"
                      className="border px-3 py-2 text-sm rounded w-full md:w-40"
                      placeholder="0"
                      value={interestFD}
                      onChange={(e) => setInterestFD(+e.target.value)}
                    />
                  </div>

                  {/* Rental income */}
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 md:gap-4">
                    <label className="text-sm md:text-base text-gray-700 w-full md:w-1/2">
                      Rental income received
                      <span className="text-xs md:text-sm text-gray-500 block md:inline">
                        {" "}(Let-out property)
                      </span>
                    </label>
                    <input
                      type="number"
                      className="border px-3 py-2 text-sm rounded w-full md:w-40"
                      placeholder="0"
                      value={rentalIncome}
                      onChange={(e) => setRentalIncome(+e.target.value)}
                    />
                  </div>

                  {/* Municipal tax */}
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 md:gap-4">
                    <label className="text-sm md:text-base text-gray-700 w-full md:w-1/2">
                      Municipal tax paid
                      <span className="text-xs md:text-sm text-gray-500 block md:inline">
                        {" "}(Let-out property)
                      </span>
                    </label>
                    <input
                      type="number"
                      className="border px-3 py-2 text-sm rounded w-full md:w-40"
                      placeholder="0"
                      value={municipalTax}
                      onChange={(e) => setMunicipalTax(+e.target.value)}
                    />
                  </div>

                  {/* Housing loan interest */}
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 md:gap-4">
                    <label className="text-sm md:text-base text-gray-700 w-full md:w-1/2">
                      Interest paid on housing loan
                      <span className="text-xs md:text-sm text-gray-500 block md:inline">
                        {" "}(Let-out property)
                      </span>
                    </label>
                    <input
                      type="number"
                      className="border px-3 py-2 text-sm rounded w-full md:w-40"
                      placeholder="0"
                      value={letOutLoanInterest}
                      onChange={(e) => setLetOutLoanInterest(+e.target.value)}
                    />
                  </div>

                  {/* Other income */}
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 md:gap-4">
                    <label className="text-sm md:text-base text-gray-700 w-full md:w-1/2">
                      Other income, if any
                    </label>
                    <input
                      type="number"
                      className="border px-3 py-2 text-sm rounded w-full md:w-40"
                      placeholder="0"
                      value={otherMiscIncome}
                      onChange={(e) => setOtherMiscIncome(+e.target.value)}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* EXEMPTION DETAILS */}
          <h2 className="text-indigo-600 font-semibold text-base md:text-lg mt-6 md:mt-8 mb-4 flex items-center gap-1">
            Exemption details
            <span className="text-gray-400 text-sm">ⓘ</span>
          </h2>

          <div className="space-y-4 md:space-y-6">
            {[
              { label: "HRA and other exemptions", value: hra, setter: setHra },
              {
                label: "Interest paid on housing loan",
                value: housingLoan,
                setter: setHousingLoan,
                limit: "₹2,00,000",
              },
              {
                label: "80C (PF, PPF, insurance premium)",
                value: sec80C,
                setter: set80C,
                limit: "₹1,50,000",
              },
              {
                label: "80CCD (Employee's contribution to NPS)",
                value: sec80CCD,
                setter: set80CCD,
                limit: "₹1,50,000",
              },
              {
                label: "80CCD(1B) (Additional contribution to NPS)",
                value: sec80CCD1B,
                setter: set80CCD1B,
                limit: "₹50,000",
              },
              {
                label: "80D (Medical insurance premium)",
                value: sec80D,
                setter: set80D,
              },
              {
                label: "80E (Interest paid on education loan)",
                value: sec80E,
                setter: set80E,
              },
              {
                label: "80EEA (Home loan – affordable housing)",
                value: sec80EEA,
                setter: set80EEA,
                limit: "₹1,50,000",
              },
            ].map((item, idx) => (
              <div key={idx} className="mb-3 md:mb-0">
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 md:gap-6">
                  <label className="text-sm md:text-base text-gray-800 w-full md:w-1/2">
                    {item.label}
                  </label>
                  <div className="w-full md:w-44">
                    <input
                      type="number"
                      value={item.value}
                      onChange={(e) => item.setter(Number(e.target.value))}
                      className="w-full px-3 py-2 md:py-1.5 text-sm border rounded"
                    />
                    {item.limit && (
                      <p className="text-xs text-gray-500 text-right md:text-right mt-1">
                        Exemption Limit: {item.limit}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* BUTTON BELOW CARD */}
          <div className="max-w-2xl mx-auto mt-4 md:mt-4 flex justify-center">
            <button
              onClick={() => setShowResult(true)}
              className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white font-semibold py-2 md:py-2 px-5 md:px-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-200 w-full md:w-auto text-sm md:text-base"
            >
              Calculate Income Tax
            </button>
          </div>
        </div>
      ) : (
        /* RESULTS SECTION - Made responsive */
        <div className="max-w-3xl mx-auto">
          <div className="bg-white rounded-lg md:rounded-xl shadow-lg overflow-hidden">
            <div className="p-2 md:p-4">
              <h3 className="text-base md:text-lg font-bold text-gray-800 mb-4">
                Here is the tax summary based on your input
              </h3>

              {/* TAX COMPARISON CARDS - Stack on mobile */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 md:gap-6 mb-6">
                {/* OLD REGIME */}
                <div className="bg-gray-50 border border-gray-200 rounded-lg p-2">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs md:text-sm font-medium text-gray-600">
                      Old Tax Regime
                    </span>
                    <span className="text-[10px] md:text-xs bg-gray-200 text-gray-700 px-2 py-1 rounded">
                      {activeFY === "current" ? "FY 2025-26" : "FY 2024-25"}
                    </span>
                  </div>

                  <div className="text-xl md:text-xl font-bold text-gray-800 mb-3">
                    {formatCurrency(oldTotal)}
                  </div>

                  <div className="text-xs md:text-sm text-gray-600 space-y-1">
                    <div>Gross Income: {formatCurrency(grossIncome)}</div>
                    <div>Deductions: {formatCurrency(oldDeductions)}</div>
                    <div>Taxable: {formatCurrency(oldTaxable)}</div>
                  </div>
                </div>

                {/* NEW REGIME */}
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs md:text-sm font-medium text-blue-600">
                      New Tax Regime
                    </span>
                    <span className="text-[10px] md:text-xs bg-blue-200 text-blue-700 px-2 py-1 rounded">
                      {activeFY === "current" ? "FY 2025-26" : "FY 2024-25"}
                    </span>
                  </div>

                  <div className="text-xl md:text-xl font-bold text-blue-800 mb-3">
                    {formatCurrency(newTotal)}
                  </div>

                  <div className="text-sm md:text-sm text-blue-600 space-y-1">
                    <div>Gross Income: {formatCurrency(grossIncome)}</div>
                    <div>
                      Standard Deduction: {formatCurrency(STANDARD_DEDUCTION)}
                    </div>
                    <div>Taxable: {formatCurrency(newTaxable)}</div>
                  </div>
                </div>

                {/* SAVINGS */}
                <div
                  className={`rounded-lg p-4 ${
                    saving > 0
                      ? "bg-gradient-to-br from-green-50 to-emerald-50 border border-green-200"
                      : "bg-gradient-to-br from-amber-50 to-orange-50 border border-amber-200"
                  }`}
                >
                  <p className="text-xs md:text-sm font-medium text-gray-700 mb-1">
                    You will save
                  </p>

                  <p
                    className={`text-xl md:text-xl font-bold mb-2 ${
                      saving > 0 ? "text-green-600" : "text-amber-600"
                    }`}
                  >
                    {formatCurrency(Math.abs(saving))}
                  </p>

                  <p className="text-xs md:text-sm text-gray-600">
                    {saving > 0
                      ? "Under the New Tax Regime"
                      : "Under the Old Tax Regime"}
                  </p>

                  <div
                    className={`mt-3 text-xs md:text-sm px-3 py-1.5 rounded inline-block ${
                      saving > 0
                        ? "bg-green-100 text-green-800"
                        : "bg-amber-100 text-amber-800"
                    }`}
                  >
                    💡 Recommended: {saving > 0 ? "New Regime" : "Old Regime"}
                  </div>
                </div>
              </div>

              {/* DETAILED BREAKDOWN - Scrollable on mobile */}
              <div className="border rounded-lg overflow-hidden mb-6">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs md:text-sm">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="text-left p-3 font-medium text-gray-700 whitespace-nowrap">
                          Components
                        </th>
                        <th className="text-left p-3 font-medium text-gray-700 whitespace-nowrap">
                          Old Tax Regime
                        </th>
                        <th className="text-left p-3 font-medium text-gray-700 whitespace-nowrap">
                          New Tax Regime
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y">
                      <tr>
                        <td className="p-3 font-medium whitespace-nowrap">Total Gross Income</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(grossIncome)}</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(grossIncome)}</td>
                      </tr>
                      <tr>
                        <td className="p-3 font-medium whitespace-nowrap">Total Eligible Deductions</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(oldDeductions)}</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(STANDARD_DEDUCTION)}</td>
                      </tr>
                      <tr className="bg-gray-50">
                        <td className="p-3 font-medium whitespace-nowrap">Taxable Income</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(oldTaxable)}</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(newTaxable)}</td>
                      </tr>
                      <tr>
                        <td className="p-3 font-medium">
                          <div>Tax on Taxable Income</div>
                          <div className="text-xs text-gray-500 mt-1 whitespace-nowrap">
                            Click to see slab breakup
                          </div>
                        </td>
                        <td className="p-3">
                          <div className="flex flex-col md:flex-row md:items-center gap-2">
                            <span className="whitespace-nowrap">{formatCurrency(oldTax)}</span>
                            <button
                              onClick={() => setShowBreakup("old")}
                              className="text-blue-600 hover:text-blue-800 font-medium text-xs px-3 py-1.5 bg-blue-50 hover:bg-blue-100 rounded transition whitespace-nowrap"
                            >
                              Show BreakUp
                            </button>
                          </div>
                        </td>
                        <td className="p-3">
                          <div className="flex flex-col md:flex-row md:items-center gap-2">
                            <span className="whitespace-nowrap">{formatCurrency(newTax)}</span>
                            <button
                              onClick={() => setShowBreakup("new")}
                              className="text-blue-600 hover:text-blue-800 font-medium text-xs px-3 py-1.5 bg-blue-50 hover:bg-blue-100 rounded transition whitespace-nowrap"
                            >
                              Show BreakUp
                            </button>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td className="p-3 font-medium whitespace-nowrap">Less: Rebate Under Section 87A</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(0)}</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(0)}</td>
                      </tr>
                      <tr>
                        <td className="p-3 font-medium whitespace-nowrap">Less: Relief Under Section 89</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(0)}</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(0)}</td>
                      </tr>
                      <tr>
                        <td className="p-3 font-medium whitespace-nowrap">Total Tax on Income</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(oldTax)}</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(newTax)}</td>
                      </tr>
                      <tr>
                        <td className="p-3 font-medium whitespace-nowrap">Surcharge</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(0)}</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(0)}</td>
                      </tr>
                      <tr>
                        <td className="p-3 font-medium whitespace-nowrap">Health and Education Cess (4%)</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(oldCess)}</td>
                        <td className="p-3 whitespace-nowrap">{formatCurrency(newCess)}</td>
                      </tr>
                      <tr className="bg-gray-100 font-bold">
                        <td className="p-3 text-sm md:text-base whitespace-nowrap">Total Tax to be Paid</td>
                        <td className="p-3 text-lg md:text-xl text-gray-800 whitespace-nowrap">
                          {formatCurrency(oldTotal)}
                        </td>
                        <td className="p-3 text-lg md:text-xl text-gray-800 whitespace-nowrap">
                          {formatCurrency(newTotal)}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* ACTION BUTTONS - Stack on mobile */}
              <div className="flex flex-col md:flex-row gap-3 md:gap-4">
                <button
                  onClick={() => setShowResult(false)}
                  className="flex-1 border-2 border-gray-300 hover:border-gray-400 text-gray-700 font-medium py-3 md:py-2 px-4 rounded-lg hover:bg-gray-50 transition text-sm md:text-base"
                >
                  Edit Data
                </button>
                <button
                  onClick={() => {
                    setShowResult(false);
                    setSalary(0);
                    setHra(0);
                    setHousingLoan(0);
                    set80C(0);
                    set80CCD(0);
                    set80CCD1B(0);
                    set80D(0);
                    set80E(0);
                    set80EEA(0);
                    set80EEB(0);
                    set80G(0);
                    setLetOutLoanInterest(0);
                    setRentalIncome(0);
                    setMunicipalTax(0);
                    setOtherMiscIncome(0);
                    setInterestFD(0);
                  }}
                  className="flex-1 border-2 border-red-300 hover:border-red-400 text-red-700 font-medium py-3 md:py-2 px-4 rounded-lg hover:bg-red-50 transition text-sm md:text-base"
                >
                  Reset All
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* BREAKUP MODAL - Made responsive */}
      {showBreakup && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-3 md:p-4 z-50">
          <div className="bg-white rounded-lg md:rounded-md shadow-lg w-full max-w-4xl overflow-hidden max-h-[90vh] overflow-y-auto">
            {/* HEADER */}
            <div className="p-4 md:p-6 border-b">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="text-base md:text-lg font-semibold text-gray-800">
                    Income Tax Slab Breakup –{" "}
                    {showBreakup === "old" ? "Old Regime" : "New Regime"}
                  </h3>
                  <p className="text-xs md:text-sm text-gray-600 mt-1">
                    {activeFY === "current"
                      ? "Financial Year 2025-2026"
                      : "Financial Year 2024-2025"}
                  </p>
                </div>
                <button
                  onClick={() => setShowBreakup(null)}
                  className="text-gray-400 hover:text-gray-600 text-2xl md:text-xl"
                >
                  ×
                </button>
              </div>
            </div>

            {/* BODY */}
            <div className="p-3 md:p-4">
              <div className="space-y-2 md:space-y-3">
                {(showBreakup === "old"
                  ? oldCalc.breakup
                  : newCalc.breakup
                ).map((b, i) => (
                  <div
                    key={i}
                    className="flex flex-col md:flex-row items-start md:items-center justify-between p-3 md:p-4 bg-gray-50 rounded-lg gap-2 md:gap-0"
                  >
                    <div className="w-full md:w-2/5">
                      <div className="text-xs md:text-sm font-medium text-gray-800 break-words">
                        {b.label}
                      </div>
                    </div>

                    <div className="w-full md:w-1/5 md:text-center">
                      <div className="text-[10px] md:text-xs text-gray-600">Rate</div>
                      <div className="text-sm md:text-base font-medium text-gray-800">
                        {b.rate}
                      </div>
                    </div>

                    <div className="w-full md:w-2/5 md:text-right">
                      <div className="text-[10px] md:text-xs text-gray-600">
                        Tax Amount
                      </div>
                      <div className="text-sm md:text-base font-semibold text-gray-800">
                        {formatCurrency(b.tax)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* TOTAL SUMMARY */}
              <div className="p-4 md:p-5 bg-blue-50 border border-blue-200 rounded-lg mt-4">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 md:gap-0">
                  <div>
                    <div className="text-xs md:text-sm text-blue-600">Total Tax</div>
                    <div className="text-lg md:text-xl font-bold text-blue-800">
                      {formatCurrency(showBreakup === "old" ? oldTax : newTax)}
                    </div>
                  </div>

                  <div className="md:text-right">
                    <div className="text-xs md:text-sm text-blue-600">Cess (4%)</div>
                    <div className="text-sm md:text-base font-medium text-blue-800">
                      {formatCurrency(
                        showBreakup === "old" ? oldCess : newCess
                      )}
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-4 border-t border-blue-200">
                  <div className="flex justify-between items-center">
                    <div className="text-sm md:text-base font-medium text-gray-700">
                      Total Payable
                    </div>
                    <div className="text-lg md:text-xl font-bold text-gray-900">
                      {formatCurrency(
                        showBreakup === "old" ? oldTotal : newTotal
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* FOOTER */}
            <div className="p-4 md:p-6 border-t flex justify-center">
              <button
                onClick={() => setShowBreakup(null)}
                className="w-full md:w-32 bg-blue-600 hover:bg-blue-700 text-white text-sm md:text-base font-medium py-3 md:py-2 rounded-lg transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IncomeTaxCalculator;
