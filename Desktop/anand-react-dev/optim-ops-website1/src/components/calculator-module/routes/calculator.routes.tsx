// import { Routes, Route, Navigate } from "react-router-dom";
// import { CALCULATOR_REGISTRY } from "../config/calculator.registry";



// export const CalculatorRoutes = () => {
//   const enabledCalculators = CALCULATOR_REGISTRY.filter(c => c.enabled);

//   return (
//     <Routes>
//       {/* Default redirect */}
//       {enabledCalculators.length > 0 && (
//         <Route
//           path="/"
//           element={<Navigate to={enabledCalculators[0].path.replace("/calculators/", "")} />}
//         />
//       )}

//       {enabledCalculators.map(calc => (
//         <Route
//           key={calc.id}
//           path={calc.path.replace("/calculators/", "")}
//           element={<calc.component />}
//         />
//       ))}
//     </Routes>
//   );
// };

import { Navigate, Route, Routes } from "react-router-dom";
import CalculatorSidebar from "../CalculatorSidebar";
import { CALCULATOR_REGISTRY } from "../config/calculator.registry";

export const CalculatorRoutes = () => {
  const enabledCalculators = CALCULATOR_REGISTRY.filter(c => c.enabled);

  return (
    <div className="min-h-screen flex bg-gray-50">
      
      {/* Sidebar */}
      <CalculatorSidebar />

      {/* Calculator Content */}
      <main className="flex-1 p-6">
        <Routes>
          {enabledCalculators.length > 0 && (
            <Route
              path="/"
              element={
                <Navigate
                  to={enabledCalculators[0].path.replace("/calculators/", "")}
                />
              }
            />
          )}

          {enabledCalculators.map(calc => (
            <Route
              key={calc.id}
              path={calc.path.replace("/calculators/", "")}
              element={<calc.component />}
            />
          ))}
        </Routes>
      </main>

    </div>
  );
};
