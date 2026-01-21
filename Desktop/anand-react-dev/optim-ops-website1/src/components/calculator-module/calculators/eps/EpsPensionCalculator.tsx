
import { Calculator } from "lucide-react";
import { useState } from "react";

export default function EpfoPensionCalculator() {
  const [salary, setSalary] = useState<number>(0);
  const [service, setService] = useState<number>(0);
  const [result, setResult] = useState<number | null>(null);
  const [showContent, setShowContent] = useState<boolean>(false);

  const SALARY_CAP = 15000;
  const SERVICE_CAP = 35;

  const calculatePension = () => {
    const cappedSalary = Math.min(salary, SALARY_CAP);
    const cappedService = Math.min(service, SERVICE_CAP);

    const pension = (cappedSalary * cappedService) / 70;
    setResult(Number(pension.toFixed(2)));
    setShowContent(true);
  };

  const [errors, setErrors] = useState<{
    salary?: string;
    service?: string;
  }>({});

  const validateForm = () => {
    const newErrors: typeof errors = {};

    if (!salary || salary <= 0) {
      newErrors.salary = "Please enter a valid salary greater than 0";
    }

    if (!service || service <= 0) {
      newErrors.service = "Please enter valid service years greater than 0";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  return (
    <div className="max-w-3xl mx-auto bg-white p-4 md:p-6 lg:p-8 rounded-xl shadow-lg">

         {/* HEADER */}
        <div className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 p-6 rounded-xl">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Calculator className="w-6 h-6 text-white" />
            <h1 className="text-2xl  text-white font-bold">  EPFO Pension Calculator</h1>
          </div>
          <p className="text-center text-white text-sm">
         Accurate EPFO pension estimation based on EPS rules, salary limits, and years of service.
          </p>
        </div>

      {/* INPUT SECTION */}
      <div className="bg-blue-50 p-4 md:p-6 rounded-xl mb-6 md:mb-8 border border-blue-100">
        <h2 className="text-lg md:text-xl font-semibold text-blue-800 mb-4">
          EPFO Pension Calculator
        </h2>

        <div className="space-y-4 md:space-y-0 md:grid md:grid-cols-2 gap-4 md:gap-6">
          <div>
            <label className="block text-sm md:text-base font-medium text-gray-700 mb-2">
              Average Monthly Salary (Basic + DA)
            </label>
            <input
              type="number"
              value={salary}
              placeholder="Max : ₹15,000"
              onChange={(e) => setSalary(Number(e.target.value))}
              className="w-full border border-gray-300 rounded-lg p-3 md:p-2 text-sm md:text-base focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
              min="0"
            />
            {errors.salary && (
              <p className="text-xs md:text-sm text-red-600 mt-1">{errors.salary}</p>
            )}
            <p className="text-xs text-gray-500 mt-2">
              Maximum considered: ₹15,000
            </p>
          </div>

          <div>
            <label className="block text-sm md:text-base font-medium text-gray-700 mb-2">
              Pensionable Service (Years)
            </label>
            <input
              type="number"
              value={service}
              placeholder="Max : 35 years"
              onChange={(e) => setService(Number(e.target.value))}
              className="w-full border border-gray-300 rounded-lg p-3 md:p-2 text-sm md:text-base focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
              min="0"
              max="50"
            />
            {errors.service && (
              <p className="text-xs md:text-sm text-red-600 mt-1">{errors.service}</p>
            )}
            <p className="text-xs text-gray-500 mt-2">
              Maximum allowed: 35 years
            </p>
          </div>
        </div>

        <button
          onClick={() => {
            if (validateForm()) {
              calculatePension();
            }
          }}
          className="mt-6 w-full md:w-auto min-w-[200px] bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white font-semibold py-3 md:py-2 px-4 md:px-6 rounded-lg transition duration-300 transform hover:scale-[1.02] text-sm md:text-base"
        >
          Calculate Pension
        </button>
      </div>

      {/* RESULT SECTION */}
      {result !== null && (
        <div className="mb-8 md:mb-10">
          <div className="bg-green-50 border border-green-200 rounded-xl p-2 md:p-4 mb-4 md:mb-4">
            <h2 className=" md:text-xl font-bold text-green-800 mb-2">
              Estimated Monthly Pension
            </h2>
            <div className="text-2xl md:text-3xl font-bold text-green-900">₹{result}</div>
            <p className="text-sm md:text-base text-green-700 mt-2">per month</p>
          </div>

          {/* CALCULATION EXPLANATION */}
          <div className="bg-gray-50 p-4 md:p-6 rounded-xl mb-6 md:mb-8">
            <h3 className="text-lg md:text-xl font-semibold text-gray-800 mb-4">
              🧮 How this pension is calculated
            </h3>

            <div className="space-y-4">
              <div className="bg-white p-3 md:p-4 rounded-lg border">
                <p className="font-medium text-gray-700 mb-1 text-sm md:text-base">
                  Step 1: Salary Adjustment
                </p>
                <p className="text-gray-600 text-sm md:text-base">
                  Salary entered = ₹{salary}
                  <br />
                  Salary capped to ₹15,000 →{" "}
                  <span className="font-semibold">
                    ₹{Math.min(salary, SALARY_CAP)}
                  </span>
                </p>
              </div>

              <div className="bg-white p-3 md:p-4 rounded-lg border">
                <p className="font-medium text-gray-700 mb-1 text-sm md:text-base">
                  Step 2: Service Adjustment
                </p>
                <p className="text-gray-600 text-sm md:text-base">
                  Service entered = {service} years
                  <br />
                  Service capped to 35 years →{" "}
                  <span className="font-semibold">
                    {Math.min(service, SERVICE_CAP)} years
                  </span>
                </p>
              </div>

              <div className="bg-white p-3 md:p-4 rounded-lg border">
                <p className="font-medium text-gray-700 mb-1 text-sm md:text-base">
                  Step 3: EPS Formula Application
                </p>
                <div className="bg-blue-50 p-3 rounded border-l-4 border-blue-500 font-mono text-sm my-2 text-xs md:text-sm">
                  (Salary × Service) ÷ 70
                </div>
                <p className="text-gray-600 text-sm md:text-base">
                  = ({Math.min(salary, SALARY_CAP)} ×{" "}
                  {Math.min(service, SERVICE_CAP)}) ÷ 70
                </p>
                <p className="font-semibold text-green-700 text-base md:text-lg mt-2">
                  = ₹{result} per month
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ADDITIONAL CONTENT - Only shows after calculation */}
      {showContent && (
        <div className="space-y-6 md:space-y-8 mt-8 md:mt-10 border-t pt-6 md:pt-8">
          {/* What is EPS */}
          <div className="bg-blue-50 p-4 md:p-6 rounded-xl">
            <h2 className="text-xl md:text-2xl font-bold text-gray-900 mb-3 md:mb-4">
              What is EPS?
            </h2>
            <p className="text-gray-700 leading-relaxed text-sm md:text-base">
              EPS (Employees' Pension Scheme) is a retirement benefit provided
              by the Employees' Provident Fund Organisation (EPFO) for employees
              in the organized sector. It ensures a monthly pension after
              retirement, based on your salary and years of service.
            </p>
          </div>

          {/* EPS Pension Formula */}
          <div className="bg-gray-50 p-4 md:p-6 rounded-xl">
            <h2 className="text-xl md:text-2xl font-bold text-gray-900 mb-3 md:mb-4">
              🧮 EPS Pension Formula
            </h2>
            <p className="text-gray-700 mb-3 md:mb-4 text-sm md:text-base">
              The pension amount is calculated using the following formula:
            </p>
            <div className="bg-white p-3 md:p-5 rounded-lg border-2 border-blue-200 mb-3 md:mb-4 overflow-x-auto">
              <div className="text-center text-lg md:text-2xl font-bold text-blue-800 whitespace-nowrap">
                EPS Pension = (Average Salary × Pensionable Service) / 70
              </div>
            </div>
            <ul className="space-y-2 md:space-y-3 text-gray-700 text-sm md:text-base">
              <li className="flex items-start">
                <span className="inline-block w-2 h-2 bg-blue-500 rounded-full mt-2 mr-2 md:mr-3 flex-shrink-0"></span>
                <span>
                  <strong>Average Salary:</strong> This is the average of your
                  last 12 months' Basic + Dearness Allowance (DA). It is capped
                  at ₹15,000.
                </span>
              </li>
              <li className="flex items-start">
                <span className="inline-block w-2 h-2 bg-blue-500 rounded-full mt-2 mr-2 md:mr-3 flex-shrink-0"></span>
                <span>
                  <strong>Pensionable Service:</strong> The total number of
                  years you contributed to EPS. Maximum allowed is 35 years.
                </span>
              </li>
            </ul>

            <div className="mt-4 md:mt-6 p-3 md:p-4 bg-green-50 border border-green-200 rounded-lg">
              <h3 className="font-semibold text-green-800 mb-2 text-sm md:text-base">Example:</h3>
              <p className="text-gray-700 text-sm md:text-base">
                If your average salary is ₹15,000 and you have 35 years of
                service:
                <br />
                <span className="font-mono text-green-900 font-semibold text-sm md:text-base">
                  EPS = (15,000 × 35) / 70 = ₹7,500/month
                </span>
              </p>
            </div>
          </div>

          {/* Contribution Breakdown */}
          <div className="bg-white p-4 md:p-6 rounded-xl border border-blue-100">
            <h2 className="text-xl md:text-2xl font-bold text-gray-900 mb-3 md:mb-4">
              💸 Contribution Breakdown
            </h2>
            <p className="text-gray-700 mb-3 md:mb-4 text-sm md:text-base">Every month:</p>
            <div className="space-y-4 md:space-y-0 md:grid md:grid-cols-2 gap-4 md:gap-6">
              <div className="bg-blue-50 p-3 md:p-4 rounded-lg">
                <h3 className="font-semibold text-blue-800 mb-2 text-sm md:text-base">
                  Employee Contribution
                </h3>
                <p className="text-gray-700 text-sm md:text-base">12% of Basic + DA to EPF</p>
              </div>
              <div className="bg-green-50 p-3 md:p-4 rounded-lg">
                <h3 className="font-semibold text-green-800 mb-2 text-sm md:text-base">
                  Employer Contribution
                </h3>
                <p className="text-gray-700 text-sm md:text-base">12% split as:</p>
                <ul className="text-gray-700 mt-2 space-y-1 text-sm md:text-base">
                  <li className="flex items-center">
                    <span className="w-2 h-2 bg-green-500 rounded-full mr-2 flex-shrink-0"></span>
                    8.33% goes to EPS
                  </li>
                  <li className="flex items-center">
                    <span className="w-2 h-2 bg-green-500 rounded-full mr-2 flex-shrink-0"></span>
                    3.67% goes to EPF
                  </li>
                </ul>
              </div>
            </div>
          </div>

          {/* Early Pension Option */}
          <div className="bg-yellow-50 p-4 md:p-6 rounded-xl border border-yellow-100">
            <h2 className="text-xl md:text-2xl font-bold text-gray-900 mb-3 md:mb-4">
              ⏳ Early Pension Option
            </h2>
            <p className="text-gray-700 mb-3 md:mb-4 text-sm md:text-base">
              You can opt for pension from age 50, but it comes with a
              reduction:
            </p>
            <div className="bg-white p-3 md:p-4 rounded-lg mb-3 md:mb-4">
              <p className="text-base md:text-lg font-semibold text-yellow-800 mb-2">
                4% reduction per year before the age of 58.
              </p>
              <p className="text-gray-700 text-sm md:text-base">
                For example, if you retire at 54, your pension will be reduced
                by 16%.
              </p>
            </div>
          </div>

          {/* How to Use Calculator */}
          <div className="bg-purple-50 p-4 md:p-6 rounded-xl">
            <h2 className="text-xl md:text-2xl font-bold text-gray-900 mb-3 md:mb-4">
              🧰 How to Use the EPFO Pension Calculator
            </h2>
            <p className="text-gray-700 mb-3 md:mb-4 text-sm md:text-base">
              This calculator helps you estimate your monthly pension based on
              your salary and service years.
            </p>
            <div className="bg-white p-3 md:p-5 rounded-lg border-l-4 border-purple-500">
              <h3 className="font-semibold text-purple-800 mb-3 text-sm md:text-base">Steps:</h3>
              <ol className="space-y-2 md:space-y-3 text-gray-700 text-sm md:text-base">
                <li className="flex items-start">
                  <span className="bg-purple-100 text-purple-800 rounded-full w-6 h-6 flex items-center justify-center mr-2 md:mr-3 flex-shrink-0 text-xs">
                    1
                  </span>
                  <span>
                    Enter your average monthly salary (Basic + DA). Maximum
                    allowed is ₹15,000.
                  </span>
                </li>
                <li className="flex items-start">
                  <span className="bg-purple-100 text-purple-800 rounded-full w-6 h-6 flex items-center justify-center mr-2 md:mr-3 flex-shrink-0 text-xs">
                    2
                  </span>
                  <span>
                    Enter your total years of pensionable service. Maximum
                    allowed is 35 years.
                  </span>
                </li>
                <li className="flex items-start">
                  <span className="bg-purple-100 text-purple-800 rounded-full w-6 h-6 flex items-center justify-center mr-2 md:mr-3 flex-shrink-0 text-xs">
                    3
                  </span>
                  <span>Click "Calculate Pension".</span>
                </li>
                <li className="flex items-start">
                  <span className="bg-purple-100 text-purple-800 rounded-full w-6 h-6 flex items-center justify-center mr-2 md:mr-3 flex-shrink-0 text-xs">
                    4
                  </span>
                  <span>
                    The calculator will display your estimated monthly pension.
                  </span>
                </li>
              </ol>
            </div>
          </div>

          {/* Min & Max Pension - Fixed grid-cols typo */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">
            <div className="bg-red-50 p-4 md:p-6 rounded-xl border border-red-100">
              <h2 className="text-lg md:text-xl font-bold text-red-800 mb-3">
                📊 Minimum Pension
              </h2>
              <div className="text-xl md:text-2xl font-bold text-red-900">₹1,000</div>
              <p className="text-red-700 mt-2 text-sm md:text-base">per month</p>
            </div>
            <div className="bg-green-50 p-4 md:p-6 rounded-xl border border-green-100">
              <h2 className="text-lg md:text-xl font-bold text-green-800 mb-3">
                📊 Maximum Pension
              </h2>
              <div className="text-xl md:text-2xl font-bold text-green-900">₹7,500</div>
              <p className="text-green-700 mt-2 text-sm md:text-base">per month</p>
            </div>
          </div>

          {/* Final Thoughts */}
          <div className="bg-gray-800 text-white p-4 md:p-6 rounded-xl">
            <h2 className="text-xl md:text-2xl font-bold mb-3 md:mb-4">📝 Final Thoughts</h2>
            <p className="text-gray-200 leading-relaxed text-sm md:text-base">
              The EPFO pension is a crucial part of retirement planning for
              salaried employees. While the current pension amounts may seem
              modest, understanding your eligibility and contributions can help
              you plan better. Use the calculator to get a quick estimate and
              make informed decisions about your retirement.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}