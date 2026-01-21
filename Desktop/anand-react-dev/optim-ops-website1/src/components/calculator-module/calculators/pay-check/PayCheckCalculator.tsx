
import { useState } from "react";
import { AlertCircle, Calculator } from "lucide-react";

/* -------------------- CONSTANTS -------------------- */

const INDIAN_STATES = [
  "Andhra Pradesh",
  "Arunachal Pradesh",
  "Assam",
  "Bihar",
  "Chhattisgarh",
  "Delhi",
  "Goa",
  "Gujarat",
  "Haryana",
  "Himachal Pradesh",
  "Jharkhand",
  "Karnataka",
  "Kerala",
  "Madhya Pradesh",
  "Maharashtra",
  "Odisha",
  "Punjab",
  "Rajasthan",
  "Tamil Nadu",
  "Telangana",
  "Uttar Pradesh",
  "Uttarakhand",
  "West Bengal",
];

const PAY_FREQUENCIES = [
  "Every week",
  "Every other week",
  "Twice a month",
  "Every month",
  "Every quarter",
  "Every year",
];

const FILING_STATUS = [
  "Single",
  "Married",
  "Married but withhold as single",
  "Head of household",
];

const format = (n: number) =>
  `₹${n.toLocaleString("en-IN", { maximumFractionDigits: 2 })}`;

/* -------------------- COMPONENT -------------------- */

const PaycheckCalculator = () => {
  const [showReceipt, setShowReceipt] = useState(false);

  /* -------- EMPLOYEE -------- */
  const [state, setState] = useState("Maharashtra");
  const [employeeName, setEmployeeName] = useState("");
  const [employeeType, setEmployeeType] = useState("Non Exempted");

  /* -------- PAY -------- */
  const [hourlyRate, setHourlyRate] = useState(0);
  const [regularHours, setRegularHours] = useState(0);
  const [overtimeHours, setOvertimeHours] = useState(0);
  const [payFrequency, setPayFrequency] = useState("Every month");
  const [payDate, setPayDate] = useState("");

  /* -------- FEDERAL -------- */
  const [filingStatus, setFilingStatus] = useState("Single");
  const [multipleJobs, setMultipleJobs] = useState("No");
  const [dependentAmount, setDependentAmount] = useState(0);
  const [otherIncome, setOtherIncome] = useState(0);
  const [deductions, setDeductions] = useState(0);
  const [additionalWithholding, setAdditionalWithholding] = useState(0);

  /* -------- STATE -------- */
  const [stateAllowances, setStateAllowances] = useState(0);
  const [stateAdditionalAllowances, setStateAdditionalAllowances] = useState(0);
  const [stateAdditionalWithholding, setStateAdditionalWithholding] =
    useState(0);

  const [errors, setErrors] = useState<{
    employeeName?: string;
    hourlyRate?: string;
    regularHours?: string;
  }>({});

  const validateForm = () => {
    const newErrors: typeof errors = {};

    if (employeeName.trim() === "") {
      newErrors.employeeName = "Employee name is required";
    }

    if (!hourlyRate || hourlyRate <= 0) {
      newErrors.hourlyRate = "Hourly rate must be greater than 0";
    }

    if (!regularHours || regularHours <= 0) {
      newErrors.regularHours = "Regular hours must be greater than 0";
    }

    setErrors(newErrors);

    return Object.keys(newErrors).length === 0;
  };

  /* -------------------- CALCULATIONS -------------------- */

  function getHourMultiplier(frequency: string) {
    switch (frequency) {
      case "Every week":
        return 1;
      case "Every other week":
        return 2;
      case "Twice a month":
        return 2.17;
      case "Every month":
        return 4.33;
      case "Every quarter":
        return 13;
      case "Every year":
        return 52;
      default:
        return 1;
    }
  }

  const weeklyRegularPay = hourlyRate * regularHours;
  const weeklyOvertimePay = hourlyRate * overtimeHours * 1.5;

  const weeklyGrossPay = weeklyRegularPay + weeklyOvertimePay;

  const multiplier = getHourMultiplier(payFrequency);

  const grossPay = weeklyGrossPay * multiplier;

  const employeePF = grossPay * 0.12;
  const incomeTax = grossPay * 0.1;

  const totalTaxes =
    employeePF + incomeTax + additionalWithholding + stateAdditionalWithholding;

  const totalDeductions = deductions;

  const netPay = Math.max(0, grossPay - totalTaxes - totalDeductions);

  /* -------------------- UI -------------------- */

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 py-8 px-4">
      <div className="max-w-2xl mx-auto ">

         {/* HEADER */}
        <div className="text-center bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 mb-4 p-4 rounded-xl">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Calculator className="w-7 h-7 text-white" />
            <h1 className="text-3xl font-bold text-white">
            Paycheck Calculator
            </h1>
          </div>
          <p className="text-white text-sm">
            Calculate net pay, taxes, and deductions for Indian employees
          </p>
        </div>

        <div className="bg-white rounded-2xl shadow-xl overflow-hidden print:shadow-none print:rounded-none">
          {!showReceipt ? (
            <div className="p-6">
              {/* ---------- EMPLOYEE ---------- */}
              <Section title="Employee Information">
                <Grid cols={3}>
                  <Input
                    label="Employee Name"
                    value={employeeName}
                    onChange={(val : string) => {
                      setEmployeeName(val);
                      setErrors({ ...errors, employeeName: undefined });
                    }}
                    error={errors.employeeName}
                    required
                  />
                  <Select
                    label="Employee Type"
                    value={employeeType}
                    onChange={setEmployeeType}
                    options={["Non Exempted", "Exempted"]}
                  />
                  <Select
                    label="State"
                    value={state}
                    onChange={setState}
                    options={INDIAN_STATES}
                  />
                </Grid>
              </Section>

              {/* ---------- PAY ---------- */}
              <Section title="Pay Information">
                <Grid cols={3}>
                  <Input
                    label="Hourly Rate"
                    type="number"
                    value={hourlyRate}
                    onChange={(val:number) => {
                      setHourlyRate(val);
                      setErrors({ ...errors, hourlyRate: undefined });
                    }}
                    error={errors.hourlyRate}
                    required
                    prefix="₹"
                  />
                  <Input
                    label="Regular Hours/Week"
                    type="number"
                    value={regularHours}
                    onChange={(val:number) => {
                      const hours = Math.min(val, 45);
                      setRegularHours(hours);
                      setErrors({ ...errors, regularHours: undefined });
                    }}
                    error={errors.regularHours}
                    required
                  />
                  <Input
                    label="Overtime Hours"
                    type="number"
                    value={overtimeHours}
                    onChange={(val:number) =>{
                      const hours = Math.min(val, 45);
                      setOvertimeHours(hours)
                    }}
                  />
                </Grid>
                <Grid cols={2}>
                  <Select
                    label="Pay Frequency"
                    value={payFrequency}
                    onChange={setPayFrequency}
                    options={PAY_FREQUENCIES}
                  />
                  <Input
                    label="Pay Date"
                    type="date"
                    value={payDate}
                    onChange={setPayDate}
                  />
                </Grid>
              </Section>

              {/* ---------- FEDERAL ---------- */}
              <Section title="Tax Information">
                <Grid cols={3}>
                  <Select
                    label="Filing Status"
                    value={filingStatus}
                    onChange={setFilingStatus}
                    options={FILING_STATUS}
                  />
                  <Select
                    label="Multiple Jobs?"
                    value={multipleJobs}
                    onChange={setMultipleJobs}
                    options={["Yes", "No"]}
                  />
                  <Input
                    label="Dependent Amount"
                    type="number"
                    value={dependentAmount}
                    onChange={setDependentAmount}
                    prefix="₹"
                  />
                </Grid>
                <Grid cols={3}>
                  <Input
                    label="Other Income"
                    type="number"
                    value={otherIncome}
                    onChange={setOtherIncome}
                    prefix="₹"
                  />
                  <Input
                    label="Deductions"
                    type="number"
                    value={deductions}
                    onChange={setDeductions}
                    prefix="₹"
                  />
                  <Input
                    label="Additional Withholding"
                    type="number"
                    value={additionalWithholding}
                    onChange={setAdditionalWithholding}
                    prefix="₹"
                  />
                </Grid>
              </Section>

              {/* ---------- STATE ---------- */}
              <Section title="State Tax Information">
                <Grid cols={3}>
                  <Input
                    label="Withholding Allowances"
                    type="number"
                    value={stateAllowances}
                    onChange={setStateAllowances}
                  />
                  <Input
                    label="Additional Allowances"
                    type="number"
                    value={stateAdditionalAllowances}
                    onChange={setStateAdditionalAllowances}
                  />
                  <Input
                    label="Additional Withholding"
                    type="number"
                    value={stateAdditionalWithholding}
                    onChange={setStateAdditionalWithholding}
                    prefix="₹"
                  />
                </Grid>
              </Section>

              <div className="flex justify-center mt-4">
                <button
                  onClick={() => {
                    if (validateForm()) {
                      setShowReceipt(true);
                    }
                  }}
                  className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white font-semibold px-8 py-3 rounded-lg shadow-lg transition-all duration-200 transform hover:scale-105"
                >
                  Calculate Paycheck
                </button>
              </div>
            </div>
          ) : (
            /* ================= RECEIPT ================= */
            <div className="p-8 print:p-6 print:max-h-screen">
              <div className="mb-4 pb-3 border-b-2 border-gray-200 print:mb-3 print:pb-2">
                <h2 className="text-2xl font-bold text-gray-900 print:text-xl">
                  Paycheck Summary
                </h2>
                <p className="text-sm text-gray-500 mt-1 print:text-xs">
                  Generated on {new Date().toLocaleDateString()}
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6 print:gap-4 print:mb-4">
                <div className="space-y-2 text-sm print:space-y-1 print:text-xs">
                  <InfoRow label="Name" value={employeeName} />
                  <InfoRow label="Employee Type" value={employeeType} />
                  <InfoRow label="State" value={state} />
                  <InfoRow label="Pay Date" value={payDate || "N/A"} />
                  <InfoRow label="Frequency" value={payFrequency} />
                </div>
                <div className="bg-gradient-to-br from-blue-50 to-indigo-50 p-6 rounded-xl border-2 border-blue-200 print:p-4 print:rounded-lg">
                  <p className="text-sm font-medium text-gray-600 mb-1 print:text-xs">
                    Net Pay
                  </p>
                  <p className="text-3xl font-bold text-blue-700 print:text-2xl">
                    {format(netPay)}
                  </p>
                  <p className="text-xs text-gray-500 mt-2 print:mt-1 print:text-[10px]">
                    After all deductions
                  </p>
                </div>
              </div>

              <div className="bg-gray-50 rounded-xl p-6 mb-6 print:p-4 print:mb-4 print:rounded-lg">
                <table className="w-full text-sm print:text-xs">
                  <thead>
                    <tr className="border-b-2 border-gray-300">
                      <th className="text-left py-3 font-semibold text-gray-700 print:py-2">
                        Description
                      </th>
                      <th className="text-right py-3 font-semibold text-gray-700 print:py-2">
                        Amount
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <Row label="Gross Pay" value={format(grossPay)} bold />
                    <tr>
                      <td colSpan={2} className="pt-4 pb-2 print:pt-2 print:pb-1">
                        <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide print:text-[10px]">
                          Deductions
                        </span>
                      </td>
                    </tr>
                    <Row label="Employee PF (12%)" value={format(employeePF)} />
                    <Row label="Income Tax (10%)" value={format(incomeTax)} />
                    {additionalWithholding > 0 && (
                      <Row
                        label="Additional Withholding"
                        value={format(additionalWithholding)}
                      />
                    )}
                    {stateAdditionalWithholding > 0 && (
                      <Row
                        label="State Withholding"
                        value={format(stateAdditionalWithholding)}
                      />
                    )}
                    {deductions > 0 && (
                      <Row label="Other Deductions" value={format(deductions)} />
                    )}
                    <tr className="border-t-2 border-gray-300">
                      <td className="py-3 font-semibold text-gray-700 print:py-2">
                        Total Deductions
                      </td>
                      <td className="py-3 text-right font-semibold text-red-600 print:py-2">
                        -{format(totalTaxes + totalDeductions)}
                      </td>
                    </tr>
                    <tr className="border-t-2 border-gray-400 bg-blue-50">
                      <td className="py-4 font-bold text-base text-gray-900 print:py-2 print:text-sm">
                        Net Pay
                      </td>
                      <td className="py-4 text-right font-bold text-lg text-blue-700 print:py-2 print:text-base">
                        {format(netPay)}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div className="flex justify-center gap-4 print:hidden">
                <button
                  onClick={() => {
                    setShowReceipt(false);
                    setErrors({});
                  }}
                  className="border-2 border-gray-300 hover:border-blue-400 px-6 py-2 rounded-lg font-medium text-gray-700 transition-colors"
                >
                  Edit Details
                </button>
                <button
                  onClick={() => window.print()}
                  className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white px-6 py-2 rounded-lg font-medium shadow-md transition-all"
                >
                  Print Paycheck
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

/* -------------------- REUSABLE UI -------------------- */

const Section = ({ title, children }: any) => (
  <div className="mb-6 pb-6 border-b border-gray-200 last:border-0">
    <h3 className="font-semibold text-gray-800 mb-4 text-base">{title}</h3>
    {children}
  </div>
);

const Grid = ({ children, cols = 3 }: any) => (
  <div className={`grid grid-cols-1 md:grid-cols-${cols} gap-4 mb-4 last:mb-0`}>
    {children}
  </div>
);

const Input = ({
  label,
  value,
  onChange,
  type = "text",
  error,
  required,
  prefix,
}: any) => (
  <div>
    <label className="block text-sm font-medium text-gray-700 mb-1.5">
      {label}
      {required && <span className="text-red-500 ml-1">*</span>}
    </label>
    <div className="relative">
      {prefix && (
        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 text-sm">
          {prefix}
        </span>
      )}
      <input
        type={type}
        value={value}
        onChange={(e) =>
          onChange(type === "number" ? +e.target.value : e.target.value)
        }
        className={`border ${
          error ? "border-red-500" : "border-gray-300"
        } ${prefix ? "pl-8" : "px-3"} py-2 rounded-lg w-full focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm`}
      />
    </div>
    {error && (
      <div className="flex items-center gap-1 mt-1 text-red-600 text-xs">
        <AlertCircle size={12} />
        <span>{error}</span>
      </div>
    )}
  </div>
);

const Select = ({ label, value, onChange, options }: any) => (
  <div>
    <label className="block text-sm font-medium text-gray-700 mb-1.5">
      {label}
    </label>
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="border border-gray-300 px-3 py-2 rounded-lg w-full focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm bg-white"
    >
      {options.map((o: string) => (
        <option key={o}>{o}</option>
      ))}
    </select>
  </div>
);

const Row = ({ label, value, bold }: any) => (
  <tr className="border-b border-gray-200">
    <td className={`py-2.5 print:py-1.5 ${bold ? "font-semibold text-gray-900" : "text-gray-700"}`}>
      {label}
    </td>
    <td className={`py-2.5 print:py-1.5 text-right ${bold ? "font-semibold text-gray-900" : "text-gray-700"}`}>
      {value}
    </td>
  </tr>
);

const InfoRow = ({ label, value }: any) => (
  <div className="flex justify-between">
    <span className="text-gray-600 font-medium">{label}:</span>
    <span className="text-gray-900">{value}</span>
  </div>
);

export default PaycheckCalculator;