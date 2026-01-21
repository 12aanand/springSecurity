

import { AlertCircle, Calculator } from "lucide-react";
import { useState, useMemo } from "react";

type Errors = {
  basic?: string;
  hra?: string;
  rent?: string;
};

export default function HraCalculator() {
  const [basic, setBasic] = useState<string>("");
  const [da, setDa] = useState<string>("");
  const [hra, setHra] = useState<string>("");
  const [rent, setRent] = useState<string>("");
  const [isMetro, setIsMetro] = useState<boolean>(true);

  const [errors, setErrors] = useState<Errors>({});
  const [touched, setTouched] = useState<Record<string, boolean>>({});

  /* ---------------- VALIDATION ---------------- */
  const validateField = (name: string, value: string) => {
    const numValue = Number(value);
    
    if (!value.trim()) {
      setErrors(prev => ({ ...prev, [name]: "Required" }));
      return false;
    }
    
    if (numValue <= 0) {
      setErrors(prev => ({ ...prev, [name]: "Must be greater than 0" }));
      return false;
    }
    
    setErrors(prev => ({ ...prev, [name]: undefined }));
    return true;
  };

  const validateAll = () => {
    let valid = true;
    
    if (!validateField("basic", basic)) valid = false;
    if (!validateField("hra", hra)) valid = false;
    if (!validateField("rent", rent)) valid = false;
    
    return valid;
  };

  /* ---------------- CALCULATION ---------------- */
  const result = useMemo(() => {
    if (!basic || !hra || !rent) return null;

    const basicVal = Number(basic);
    const daVal = Number(da || 0);
    const hraVal = Number(hra);
    const rentVal = Number(rent);

    const salary = basicVal + daVal;

    const A = Math.max(0, rentVal - 0.1 * salary);
    const B = isMetro ? 0.5 * salary : 0.4 * salary;
    const C = hraVal;

    const exempted = Math.min(A, B, C);
    const taxable = hraVal - exempted;

    return { A, B, C, exempted, taxable };
  }, [basic, da, hra, rent, isMetro]);

  const reset = () => {
    setBasic("");
    setDa("");
    setHra("");
    setRent("");
    setIsMetro(true);
    setErrors({});
    setTouched({});
  };

  const format = (n: number) =>
    n.toLocaleString("en-IN", { maximumFractionDigits: 0 });

  const handleInputChange = (
    value: string,
    setter: (val: string) => void,
    fieldName: keyof Errors
  ) => {
    setter(value);
    if (touched[fieldName]) {
      validateField(fieldName, value);
    }
  };

  const handleBlur = (fieldName: keyof Errors, value: string) => {
    setTouched(prev => ({ ...prev, [fieldName]: true }));
    validateField(fieldName, value);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 flex justify-center p-3 md:p-4 lg:p-6">
      <div className="w-full max-w-md mx-2 md:mx-auto">
     
           {/* HEADER */}
        <div className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 p-6 rounded-xl">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Calculator className="w-6 h-6 text-white" />
            <h1 className="text-2xl  text-white font-bold"> HRA Calculator</h1>
          </div>
          <p className="text-center text-white text-sm">
            Calculate HRA tax exemption under Section 10(13A)
          </p>
        </div>

        {/* FORM */}
        <div className="bg-white rounded-xl md:rounded-2xl shadow-md p-2 md:p-3 lg:p-3 space-y-2 md:space-y-2">
          {[
            {
              label: "Basic Salary (p.a)",
              value: basic,
              setter: setBasic,
              field: "basic" as keyof Errors,
              error: errors.basic,
              required: true
            },
            {
              label: "Dearness Allowance (p.a)",
              value: da,
              setter: setDa,
              field: "da" as keyof Errors,
              error: undefined,
              required: false
            },
            {
              label: "HRA Received (p.a)",
              value: hra,
              setter: setHra,
              field: "hra" as keyof Errors,
              error: errors.hra,
              required: true
            },
            {
              label: "Rent Paid (p.a)",
              value: rent,
              setter: setRent,
              field: "rent" as keyof Errors,
              error: errors.rent,
              required: true
            },
          ].map(({ label, value, setter, field, error, required }) => (
            <div key={field} className="space-y-1">
              <div className="flex items-center justify-between">
                <label className="text-sm md:text-base font-medium text-gray-700">
                  {label}
                  {required && <span className="text-red-500 ml-1">*</span>}
                </label>
                {error && (
                  <div className="flex items-center gap-1 text-red-600 text-xs md:text-sm">
                    <AlertCircle size={12} className="flex-shrink-0" />
                    <span className="hidden md:inline">{error}</span>
                    <span className="md:hidden">!</span>
                  </div>
                )}
              </div>
              <div className="relative">
                <input
                  type="number"
                  value={value}
                  onChange={(e) => handleInputChange(e.target.value, setter, field)}
                  onBlur={() => handleBlur(field, value)}
                  className={`w-full px-3 py-2 md:py-2.5 text-sm md:text-base border rounded-lg focus:ring-2 focus:outline-none transition-all ${
                    error 
                      ? "border-red-300 focus:ring-red-100 focus:border-red-500" 
                      : "border-gray-300 focus:ring-blue-100 focus:border-blue-500"
                  }`}
                  placeholder="Enter amount"
                />
                <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 text-sm md:text-base">
                  ₹
                </div>
              </div>
            </div>
          ))}

          {/* METRO CITY TOGGLE */}
          <div className="pt-1">
            <label className="block text-sm md:text-base font-medium text-gray-700 mb-2">
              Metro City Residence
            </label>
            <div className="flex border border-gray-300 rounded-lg overflow-hidden w-full max-w-64">
              <button
                onClick={() => setIsMetro(true)}
                className={`flex-1 py-2 md:py-2 text-sm md:text-base font-medium transition-colors ${
                  isMetro 
                    ? "bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white" 
                    : "bg-white text-gray-700 hover:bg-gray-50"
                }`}
              >
                Yes
              </button>
              <button
                onClick={() => setIsMetro(false)}
                className={`flex-1 py-2.5 md:py-2 text-sm md:text-base font-medium transition-colors ${
                  !isMetro 
                    ? "bg-gradient-to-br from-red-500 via-purple-400 to-indigo-700 text-white" 
                    : "bg-white text-gray-700 hover:bg-gray-50"
                }`}
              >
                No
              </button>
            </div>
            <p className="text-xs md:text-sm text-gray-500 mt-1">
              {isMetro ? "50% of salary considered" : "40% of salary considered"}
            </p>
          </div>

          {/* BUTTONS */}
          <div className="flex flex-col sm:flex-row gap-3 pt-1">
            <button
              onClick={() => {
                if (validateAll()) {
                  // Force a re-render to show results
                }
              }}
              className="flex-1 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-3xl text-white py-3 md:py-2.5 rounded-lg text-sm md:text-base font-medium transition-all shadow-sm"
            >
              Calculate Exemption
            </button>

            <button
              onClick={reset}
              className="py-3 md:py-2.5 px-4 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-400  text-white rounded-lg text-sm md:text-base font-medium hover:bg-gray-200 transition-colors whitespace-nowrap"
            >
              Reset
            </button>
          </div>

          {/* RESULT */}
          {result && (
            <div className="bg-gradient-to-br from-gray-50 to-blue-50 rounded-xl p-4 md:p-5 space-y-3 mt-4 border border-gray-200">
              <h3 className="font-semibold text-gray-800 text-sm md:text-base mb-2">Exemption Calculation</h3>
              
              <div className="space-y-2.5">
                {[
                  { label: `(A) Rent − 10% of salary`, value: result.A },
                  { label: `(B) ${isMetro ? '50%' : '40%'} of salary`, value: result.B },
                  { label: `(C) HRA received`, value: result.C },
                ].map((item, idx) => (
                  <div key={idx} className="flex justify-between items-center text-sm md:text-base">
                    <span className="text-gray-600 truncate pr-2">{item.label}</span>
                    <span className="font-medium whitespace-nowrap">₹ {format(item.value)}</span>
                  </div>
                ))}
              </div>

              <div className="border-t pt-3 space-y-2.5">
                <div className="flex justify-between items-center">
                  <span className="text-sm md:text-base font-semibold text-green-600">Exempted HRA</span>
                  <span className="text-lg md:text-xl font-bold text-green-600">₹ {format(result.exempted)}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm md:text-base font-semibold text-red-600">Taxable HRA</span>
                  <span className="text-lg md:text-xl font-bold text-red-600">₹ {format(result.taxable)}</span>
                </div>
              </div>
              
              <div className="pt-2 text-xs md:text-sm text-gray-500 text-center">
                Minimum of A, B, or C is exempted from tax
              </div>
            </div>
          )}
        </div>

        {/* FOOTER NOTE */}
        <div className="mt-4 md:mt-6 text-center text-xs md:text-sm text-gray-500 px-2">
          *All amounts are per annum (yearly)
        </div>
      </div>
    </div>
  );
}