// import { NavLink } from "react-router-dom";
// import { CALCULATOR_REGISTRY } from ".";
// // import { CALCULATOR_REGISTRY } from "../config/calculator.registry";

// const CalculatorSidebar = () => {
//   const calculators = CALCULATOR_REGISTRY.filter((c) => c.enabled);

//   return (
//     <aside className="w-64 bg-white border-r p-4">
//       <h2 className="text-lg font-bold mb-4">Calculators</h2>

//       <nav className="space-y-2">
//         {calculators.map((calc) => (
//           <NavLink
//             key={calc.id}
//             to={calc.path} // ✅ absolute path
//             className={({ isActive }) =>
//               `block px-3 py-2 rounded-lg text-sm font-medium ${
//                 isActive
//                   ? "bg-blue-600 text-white"
//                   : "text-gray-600 hover:bg-gray-100"
//               }`
//             }
//           >
//             {calc.id.replace("-", " ").toUpperCase()}
//           </NavLink>
//         ))}
//       </nav>
//     </aside>
//   );
// };

// export default CalculatorSidebar;

import { NavLink, useNavigate } from "react-router-dom";
import { CALCULATOR_REGISTRY } from ".";
// import { CALCULATOR_REGISTRY } from "../config/calculator.registry";

const CalculatorSidebar = () => {
  const calculators = CALCULATOR_REGISTRY.filter((c) => c.enabled);

  const navigate = useNavigate();

  return (
    <aside className="sticky top-0 h-screen w-64 bg- border-r border-gray-200 p-2 flex-shrink-0 overflow-y-auto">
      <div className="flex flex-col h-full">
        {/* Header */}
        {/* Header */}
        <div className="mb-8 p-4 border-b rounded-lg border-gray-100 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white">
          <button
            onClick={() => navigate("/")}
            className="flex items-center gap-2 text-sm font-semibold 
               text-white hover:text-gray-200 mb-3"
          >
            ← Back to Home
          </button>

          <h2 className="text-xl font-bold text-white">Calculators</h2>
          <p className="text-sm text-gray-100 mt-1">
            {calculators.length} tools available
          </p>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1">
          {calculators.map((calc) => (
            <NavLink
              key={calc.id}
              to={calc.path}
              className={({ isActive }) =>
                `flex items-center px-3 py-1 rounded-lg transition-all duration-200 text-sm font-medium ${
                  isActive
                    ? "bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 text-white shadow-sm"
                    : "text-gray-700 hover:bg-gray-50 hover:pl-5 hover:text-gray-900"
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {/* Optional: Add icons here if available in your registry */}
                  {/* {calc.icon && (
                    <span className="mr-3 text-lg">{calc.icon}</span>
                  )} */}
                  <span className="flex-1">
                    {calc.id || calc.id.replace(/-/g, " ").toUpperCase()}
                  </span>
                  {isActive && (
                    <span className="ml-2 w-2 h-2 bg-white rounded-full opacity-80"></span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Footer (optional) */}
        <div className="pt-6 mt-6 border-t border-gray-100">
          <p className="text-xs text-gray-400">
            Updated just now • All calculators verified
          </p>
        </div>
      </div>
    </aside>
  );
};

export default CalculatorSidebar;
