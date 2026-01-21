import { Outlet } from "react-router-dom";
import CalculatorSidebar from "./CalculatorSidebar";

// CalculatorLayout.tsx
const CalculatorLayout = () => {
  return (
    <div className="flex min-h-screen bg-gray-50">
      {/* Fixed Sidebar */}
      <div className="fixed left-0 top-0 h-screen w-64 z-10">
        <CalculatorSidebar />
      </div>
      
      {/* Main Content Area */}
      <main className="flex-1 ml-64 p-6 overflow-y-auto">
        {/* Calculator pages will render here */}
        <Outlet /> {/* If using React Router */}
      </main>
    </div>
  );
};