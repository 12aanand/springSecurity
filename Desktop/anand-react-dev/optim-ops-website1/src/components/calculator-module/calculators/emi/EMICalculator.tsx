import { Calculator } from "lucide-react";
import React, { useState, useEffect, useMemo } from "react";
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts";

const COLORS = ["#22c55e", "#ef4444"];

interface EMIResult {
  emi: number;
  totalInterest: number;
  totalPayment: number;
  principal: number;
  interestRate: number;
  tenureMonths: number;
  schedule: PaymentSchedule[];
}

interface PaymentSchedule {
  month: number;
  payment: number;
  principal: number;
  interest: number;
  outstandingBalance: number;
}

const EMICalculator: React.FC = () => {
  // State for input values
  const [principal, setPrincipal] = useState<number>(100000);
  const [interestRate, setInterestRate] = useState<number>(6);
  const [tenureYears, setTenureYears] = useState<number>(5);
  const [tenureMonths, setTenureMonths] = useState<number>(0);

  // State for results
  const [emi, setEmi] = useState<number>(0);
  const [totalInterest, setTotalInterest] = useState<number>(0);
  const [totalPayment, setTotalPayment] = useState<number>(0);
  const [paymentSchedule, setPaymentSchedule] = useState<PaymentSchedule[]>([]);

  const [expandedYear, setExpandedYear] = useState<number | null>(null);
  const [visibleYears, setVisibleYears] = useState(5);

  const toggleYear = (index: number) => {
    setExpandedYear(expandedYear === index ? null : index);
  };

  // State for active tab
  const [activeTab, setActiveTab] = useState<"details" | "schedule" | "chart">(
    "details",
  );

  // State for chart data
  const [chartData, setChartData] = useState<{
    principal: number;
    interest: number;
  }>({
    principal: 0,
    interest: 0,
  });

  const data = [
    { name: "Principal", value: chartData.principal },
    { name: "Interest", value: chartData.interest },
  ];

  // Calculate EMI when inputs change
  useEffect(() => {
    calculateEMI();
  }, [principal, interestRate, tenureYears, tenureMonths]);

  // Function to calculate EMI
  const calculateEMI = () => {
    const totalMonths = tenureYears * 12 + tenureMonths;
    const monthlyInterestRate = interestRate / 12 / 100;

    if (monthlyInterestRate === 0) {
      const emiValue = principal / totalMonths;
      setEmi(Math.round(emiValue));
      setTotalInterest(0);
      setTotalPayment(principal);
      setChartData({ principal: 100, interest: 0 });
      generatePaymentSchedule(emiValue, totalMonths, 0);
      return;
    }

    const emiValue =
      (principal *
        monthlyInterestRate *
        Math.pow(1 + monthlyInterestRate, totalMonths)) /
      (Math.pow(1 + monthlyInterestRate, totalMonths) - 1);

    const totalPaymentValue = emiValue * totalMonths;
    const totalInterestValue = totalPaymentValue - principal;

    setEmi(Math.round(emiValue));
    setTotalInterest(Math.round(totalInterestValue));
    setTotalPayment(Math.round(totalPaymentValue));

    // Calculate chart data
    const principalPercentage = (principal / totalPaymentValue) * 100;
    const interestPercentage = (totalInterestValue / totalPaymentValue) * 100;
    setChartData({
      principal: Math.round(principalPercentage * 10) / 10,
      interest: Math.round(interestPercentage * 10) / 10,
    });

    // Generate payment schedule
    generatePaymentSchedule(emiValue, totalMonths, monthlyInterestRate);
  };

  // Function to generate payment schedule
  const generatePaymentSchedule = (
    emi: number,
    totalMonths: number,
    monthlyInterestRate: number,
  ) => {
    const schedule: PaymentSchedule[] = [];
    let outstandingBalance = principal;

    for (let month = 1; month <= totalMonths; month++) {
      const interest = outstandingBalance * monthlyInterestRate;
      const principalPayment = emi - interest;
      outstandingBalance -= principalPayment;

      schedule.push({
        month,
        payment: Math.round(emi),
        principal: Math.round(principalPayment),
        interest: Math.round(interest),
        outstandingBalance: Math.max(Math.round(outstandingBalance), 0),
      });
    }

    setPaymentSchedule(schedule);
  };

  const groupByYear = (schedule: PaymentSchedule[]): PaymentSchedule[][] => {
    const years: PaymentSchedule[][] = [];

    for (let i = 0; i < schedule.length; i += 12) {
      years.push(schedule.slice(i, i + 12));
    }

    return years;
  };

  const yearlySchedule = groupByYear(paymentSchedule);

  // Format currency in Indian numbering system
  const formatCurrency = (amount: number): string => {
    return new Intl.NumberFormat("en-IN", {
      style: "currency",
      currency: "INR",
      maximumFractionDigits: 0,
    }).format(amount);
  };

  // Handle tenure changes
  const handleTenureChange = (years: number, months: number) => {
    setTenureYears(years);
    setTenureMonths(months);
  };

  // Predefined tenure options
  const tenureOptions = [
    { years: 1, months: 0, label: "1 Year" },
    { years: 3, months: 0, label: "3 Years" },
    { years: 5, months: 0, label: "5 Years" },
    { years: 10, months: 0, label: "10 Years" },
    { years: 15, months: 0, label: "15 Years" },
    { years: 20, months: 0, label: "20 Years" },
    { years: 25, months: 0, label: "25 Years" },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 py-6 px-2">
      <div className="max-w-5xl mx-auto">
        {/* HEADER */}
        <div className="text-center bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 mb-4 p-4 rounded-xl">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Calculator className="w-7 h-7 text-white" />
            <h1 className="text-3xl font-bold text-white">EMI Calculator</h1>
          </div>
          <p className="text-white text-sm">
            Calculate your Equated Monthly Installment (EMI) for home loans, car
            loans, personal loans, and more with detailed payment schedule and
            visual breakdown.
          </p>
        </div>

        <div className="flex flex-col lg:flex-row gap-8">
          {/* Left Panel - Inputs */}
          <div className="lg:w-2/5">
            <div className="bg-white rounded-2xl shadow-xl p-4 mb-6">
              <h2 className="text-xl font-semibold text-gray-800 mb-6 pb-3 border-b border-gray-200">
                Loan Details
              </h2>

              {/* Loan Amount */}
              <div className="mb-3">
                <div className="flex justify-between items-center mb-2">
                  <label className="font-medium text-gray-700">
                    Loan Amount
                  </label>
                  <span className="text-lg font-bold text-blue-600">
                    {formatCurrency(principal)}
                  </span>
                </div>
                 <input
                  type="number"
                  value={principal}
                  placeholder="00"
                  onChange={(e) => setPrincipal(parseInt(e.target.value))}
                  className="w-full px-3 py-1 border border-gray-300 rounded-lg "
                />
                <input
                  type="range"
                  min="10000"
                  max="50000000"
                  step="50000"
                  value={principal}
                  onChange={(e) => setPrincipal(parseInt(e.target.value))}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                />
                <div className="flex justify-between text-sm text-gray-500 mt-1">
                  <span>₹10,000</span>
                  <span>₹5,00,00,000</span>
                </div>
                <div className="grid grid-cols-2 gap-4 mt-2">
                  {[500000, 1000000, 2000000, 5000000].map((amount) => (
                    <button
                      key={amount}
                      onClick={() => setPrincipal(amount)}
                      className={`py-1 px-2 rounded-lg border ${principal === amount ? "bg-blue-50 border-blue-500 text-blue-600" : "border-gray-300 text-gray-700 hover:bg-gray-50"}`}
                    >
                      {formatCurrency(amount)}
                    </button>
                  ))}
                </div>
              </div>

              {/* Interest Rate */}
              <div className="mb-3">
                <div className="flex justify-between items-center mb-1">
                  <label className="font-medium text-gray-700">
                    Interest Rate (p.a.)
                  </label>
                  <span className="text-lg font-bold text-blue-600">
                    {interestRate}%
                  </span>
                </div>
                 <input
                  type="number"
                  value={interestRate}
                  placeholder="3%"
                  onChange={(e) => setInterestRate(parseFloat(e.target.value))}
                  className="w-full px-3 py-1 border border-gray-300 rounded-lg "
                />
                <input
                  type="range"
                  min="1"
                  max="20"
                  step="0.1"
                  value={interestRate}
                  onChange={(e) => setInterestRate(parseFloat(e.target.value))}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                />
                <div className="flex justify-between text-sm text-gray-500 mt-1">
                  <span>1%</span>
                  <span>20%</span>
                </div>
                <div className="grid grid-cols-5 gap-2 mt-2">
                  {[5,8,10,11, 12].map((rate) => (
                    <button
                      key={rate}
                      onClick={() => setInterestRate(rate)}
                      className={`py-1 px-1 rounded-lg border ${interestRate === rate ? "bg-blue-50 border-blue-500 text-blue-600" : "border-gray-300 text-gray-700 hover:bg-gray-50"}`}
                    >
                      {rate}%
                    </button>
                  ))}
                </div>
              </div>

              {/* Loan Tenure */}
              <div className="mb-3">
                <div className="flex justify-between items-center mb-1">
                  <label className="font-medium text-gray-700">
                    Loan Tenure
                  </label>
                  <span className="text-lg font-bold text-blue-600">
                    {tenureYears} Years{" "}
                    {tenureMonths > 0 ? `& ${tenureMonths} Months` : ""}
                  </span>
                </div>
                <div className="mb-3">
                  <input
                    type="range"
                    min="1"
                    max="30"
                    value={tenureYears}
                    onChange={(e) =>
                      handleTenureChange(parseInt(e.target.value), tenureMonths)
                    }
                    className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                  />
                  <div className="flex justify-between text-sm text-gray-500 mt-1">
                    <span>1 Year</span>
                    <span>30 Years</span>
                  </div>
                </div>

                <div className="grid grid-cols-4 sm:grid-cols-7 gap-2">
                  {tenureOptions.map((option) => (
                    <button
                      key={option.label}
                      onClick={() =>
                        handleTenureChange(option.years, option.months)
                      }
                      className={`py-2 text-sm rounded-lg border ${tenureYears === option.years && tenureMonths === option.months ? "bg-blue-50 border-blue-500 text-blue-600" : "border-gray-300 text-gray-700 hover:bg-gray-50"}`}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>

                <div className="mt-2 flex gap-4">
                  <div className="flex-1">
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Years
                    </label>
                    <input
                      type="number"
                      min="0"
                      max="30"
                      value={tenureYears}
                      onChange={(e) =>
                        handleTenureChange(
                          parseInt(e.target.value) || 0,
                          tenureMonths,
                        )
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div className="flex-1">
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Months
                    </label>
                    <input
                      type="number"
                      min="0"
                      max="11"
                      value={tenureMonths}
                      onChange={(e) =>
                        handleTenureChange(
                          tenureYears,
                          parseInt(e.target.value) || 0,
                        )
                      }
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Info Panel */}
            <div className="bg-blue-50 border border-blue-100 rounded-2xl p-4">
              <h3 className="font-semibold text-blue-800 mb-3">
                How EMI is Calculated
              </h3>
              <p className="text-blue-700 text-sm mb-3">
                EMI = [P × R × (1+R)^N] / [(1+R)^N-1]
              </p>
              <ul className="text-blue-700 text-sm space-y-2">
                <li className="flex items-start">
                  <span className="text-blue-500 mr-2">•</span>
                  <span>
                    <strong>P</strong> = Principal loan amount
                  </span>
                </li>
                <li className="flex items-start">
                  <span className="text-blue-500 mr-2">•</span>
                  <span>
                    <strong>R</strong> = Monthly interest rate (annual rate ÷ 12
                    ÷ 100)
                  </span>
                </li>
                <li className="flex items-start">
                  <span className="text-blue-500 mr-2">•</span>
                  <span>
                    <strong>N</strong> = Loan tenure in months
                  </span>
                </li>
              </ul>
            </div>
          </div>

          {/* Right Panel - Results */}
          <div className="lg:w-3/5">
            <div className="bg-white rounded-2xl shadow-xl overflow-hidden mb-6">
              {/* Result Summary */}
              <div className="p-2 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white">
                <div className="flex flex-col md:flex-row justify-between items-center">
                  <div>
                    <h2 className="text-xl font-bold">Monthly EMI</h2>
                    <p className="text-blue-100">
                      Your equated monthly installment
                    </p>
                  </div>
                  <div className="mt-4 md:mt-0">
                    <div className="text-2xl font-bold">
                      {formatCurrency(emi)}
                    </div>
                    <p className="text-blue-100 text-right">per month</p>
                  </div>
                </div>
              </div>

              {/* Financial Summary */}
              <div className="p-2">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-2">
                  <div className="bg-gray-50 p-5 rounded-xl border border-gray-200">
                    <div className="text-gray-500 text-sm mb-1">
                      Total Loan Amount
                    </div>
                    <div className="text-xl font-bold text-gray-800">
                      {formatCurrency(principal)}
                    </div>
                  </div>
                  <div className="bg-gray-50 p-5 rounded-xl border border-gray-200">
                    <div className="text-gray-500 text-sm mb-1">
                      Total Interest Payable
                    </div>
                    <div className="text-xl font-bold text-red-600">
                      {formatCurrency(totalInterest)}
                    </div>
                  </div>
                  <div className="bg-gray-50 p-5 rounded-xl border border-gray-200">
                    <div className="text-gray-500 text-sm mb-1">
                      Total Payment
                    </div>
                    <div className="text-xl font-bold text-green-600">
                      {formatCurrency(totalPayment)}
                    </div>
                  </div>
                </div>

                <div className="mb-2">
                  <h3 className="font-semibold text-gray-800 ">
                    Payment Breakdown
                  </h3>

                  <div className="flex items-center gap-10">
                    <PieChart width={220} height={220}>
                      <Pie
                        data={data}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={4}
                        dataKey="value"
                      >
                        {data.map((_, index) => (
                          <Cell key={index} fill={COLORS[index]} />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend />
                    </PieChart>

                    {/* Labels */}
                    <div>
                      <div className="flex items-center mb-2">
                        <div className="w-4 h-4 bg-green-500 rounded mr-2"></div>
                        <span>Principal: {chartData.principal}%</span>
                      </div>
                      <div className="flex items-center">
                        <div className="w-4 h-4 bg-red-500 rounded mr-2"></div>
                        <span>Interest: {chartData.interest}%</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Tabs for Details/Schedule */}
                <div className="border-b border-gray-200 mb-2">
                  <nav className="flex space-x-2">
                    <button
                      onClick={() => setActiveTab("details")}
                      className={`py-3 px-4 font-medium text-sm rounded-t-lg ${activeTab === "details" ? "bg-blue-50 text-blue-600 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
                    >
                      Loan Details
                    </button>
                    {/* <button
                      onClick={() => setActiveTab("schedule")}
                      className={`py-3 px-4 font-medium text-sm rounded-t-lg ${activeTab === "schedule" ? "bg-blue-50 text-blue-600 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
                    >
                      Payment Schedule
                    </button> */}
                    <button
                      onClick={() => setActiveTab("chart")}
                      className={`py-3 px-4 font-medium text-sm rounded-t-lg ${activeTab === "chart" ? "bg-blue-50 text-blue-600 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
                    >
                      Yearly & monthy details
                    </button>
                  </nav>
                </div>

                {/* Tab Content */}
                <div className="overflow-x-auto">
                  {activeTab === "details" && (
                    <div className="space-y-2">
                      <div className="flex justify-between py-1 border-b border-gray-100">
                        <span className="text-gray-600">Loan Amount</span>
                        <span className="font-medium">
                          {formatCurrency(principal)}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-gray-100">
                        <span className="text-gray-600">
                          Interest Rate (p.a.)
                        </span>
                        <span className="font-medium">{interestRate}%</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-gray-100">
                        <span className="text-gray-600">Loan Tenure</span>
                        <span className="font-medium">
                          {tenureYears} Years{" "}
                          {tenureMonths > 0 ? `& ${tenureMonths} Months` : ""}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-gray-100">
                        <span className="text-gray-600">
                          Total Interest Payable
                        </span>
                        <span className="font-medium text-red-600">
                          {formatCurrency(totalInterest)}
                        </span>
                      </div>
                      <div className="flex justify-between py-1">
                        <span className="text-gray-600">
                          Total Payment (Principal + Interest)
                        </span>
                        <span className="font-medium text-green-600">
                          {formatCurrency(totalPayment)}
                        </span>
                      </div>
                    </div>
                  )}

                 
                  {activeTab === "chart" && (
                    <div className="space-y-4">
                      {yearlySchedule
                        .slice(0, visibleYears)
                        .map((year, yearIndex) => {
                          const totalPrincipal = year.reduce(
                            (s, m) => s + m.principal,
                            0,
                          );
                          const totalInterest = year.reduce(
                            (s, m) => s + m.interest,
                            0,
                          );
                          const totalPayment = totalPrincipal + totalInterest;

                          return (
                            <div
                              key={yearIndex}
                              className="border border-gray-200 rounded-lg overflow-hidden"
                            >
                              {/* YEAR HEADER */}
                              <button
                                onClick={() => toggleYear(yearIndex)}
                                className="w-full flex justify-between items-center px-2 py-1 bg-gray-50 hover:bg-gray-100"
                              >
                                <div>
                                  <div className="flex ">
                                    <h4 className="text-left font-semibold text-gray-800">
                                      Year {yearIndex + 1}
                                    </h4>
                                  </div>
                                  <p className="text-sm text-gray-600">
                                    Principal: {formatCurrency(totalPrincipal)}{" "}
                                    | Interest: {formatCurrency(totalInterest)}
                                  </p>
                                </div>
                                <div className="">
                                  <h5 className="text-right justify-end items-end font-semibold text-gray-800">
                                      Total
                                    </h5>
                                    <span className="text-sm font-medium text-gray-700">
                                      {formatCurrency(totalPayment)}
                                    </span>
                                </div>
                              </button>

                              {/* MONTH TABLE */}
                              {expandedYear === yearIndex && (
                                <div className="overflow-x-auto">
                                  <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-white">
                                      <tr>
                                        <th className="px-4 py-1 text-left text-xs font-medium text-gray-500">
                                          Month
                                        </th>
                                        <th className="px-4 py-1 text-left text-xs font-medium text-gray-500">
                                          EMI
                                        </th>
                                        <th className="px-4 py-1 text-left text-xs font-medium text-gray-500">
                                          Principal
                                        </th>
                                        <th className="px-4 py-1 text-left text-xs font-medium text-gray-500">
                                          Interest
                                        </th>
                                        <th className="px-4 py-1 text-left text-xs font-medium text-gray-500">
                                          Balance
                                        </th>
                                      </tr>
                                    </thead>
                                    <tbody className="divide-y">
                                      {year.map((m, i) => (
                                        <tr
                                          key={i}
                                          className="hover:bg-gray-50"
                                        >
                                          <td className="px-4 py-1 text-sm">
                                            {yearIndex * 12 + i + 1}
                                          </td>
                                          <td className="px-4 py-1 text-sm font-medium">
                                            {formatCurrency(m.payment)}
                                          </td>
                                          <td className="px-4 py-1 text-sm text-green-600">
                                            {formatCurrency(m.principal)}
                                          </td>
                                          <td className="px-4 py-1 text-sm text-red-600">
                                            {formatCurrency(m.interest)}
                                          </td>
                                          <td className="px-4 py-1 text-sm">
                                            {formatCurrency(
                                              m.outstandingBalance,
                                            )}
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              )}
                            </div>
                          );
                        })}

                      {/* LOAD MORE YEARS */}
                      {yearlySchedule.length > visibleYears && (
                        <div className="text-center">
                          <button
                            onClick={() =>
                              setVisibleYears(yearlySchedule.length)
                            }
                            className="mt-4 px-6 py-2 text-sm font-medium text-blue-600 border border-blue-600 rounded-md hover:bg-blue-50"
                          >
                            Load more years
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-col sm:flex-row gap-4">
              <button
                className="flex-1 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white font-medium py-2 px-4 rounded-xl transition duration-200 flex items-center justify-center"
                onClick={() => {
                  const data = {
                    principal,
                    interestRate,
                    tenureYears,
                    tenureMonths,
                    emi,
                    totalInterest,
                    totalPayment,
                  };
                  alert(
                    `EMI Calculation Summary:\n\nLoan Amount: ${formatCurrency(principal)}\nInterest Rate: ${interestRate}%\nTenure: ${tenureYears} Years ${tenureMonths > 0 ? `& ${tenureMonths} Months` : ""}\n\nMonthly EMI: ${formatCurrency(emi)}\nTotal Interest: ${formatCurrency(totalInterest)}\nTotal Payment: ${formatCurrency(totalPayment)}`,
                  );
                }}
              >
                <svg
                  className="w-5 h-5 mr-2"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                  ></path>
                </svg>
                Download Summary
              </button>
              <button
                className="flex-1 bg-white hover:bg-gray-50 text-blue-600 font-medium py-1 px-3 rounded-xl border border-blue-600 transition duration-200 flex items-center justify-center"
                onClick={() => {
                  setPrincipal(500000);
                  setInterestRate(8.5);
                  setTenureYears(20);
                  setTenureMonths(0);
                }}
              >
                <svg
                  className="w-5 h-5 mr-2"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                  ></path>
                </svg>
                Reset Calculator
              </button>
            </div>
          </div>
        </div>

        {/* Footer Note */}
        <div className="mt-10 text-center text-gray-500 text-sm">
          <p>
            This EMI calculator provides approximate values. Actual loan terms
            may vary based on the lender's policies and your credit profile.
          </p>
          <p className="mt-2">
            © {new Date().getFullYear()} Professional EMI Calculator. For
            demonstration purposes.
          </p>
        </div>
      </div>
    </div>
  );
};

export default EMICalculator;
