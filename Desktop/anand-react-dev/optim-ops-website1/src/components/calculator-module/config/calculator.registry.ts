import GstCalculator from "../calculators/gst/GstCalculator";
import DiscountCalculator from "../calculators/dicount/DiscountCalculator";
import IncomeTaxCalculator from "../calculators/incom-tax/IncomeTaxCalculator";
import PaycheckCalculator from "../calculators/pay-check/PayCheckCalculator";
import VatCalculator from "../calculators/gst/VatCalculator";
import GratuityCalculator from "../calculators/gratuity/GratuityCalculator";
import NpsCalculator from "../calculators/nps/NpsCalculator";
import HraCalculator from "../calculators/hra/HraCalculation";
import EpsPensionCalculator from "../calculators/eps/EpsPensionCalculator";
import EMICalculator from "../calculators/emi/EMICalculator";

export const CALCULATOR_REGISTRY = [
  {
    id: "GST Calculator",
    path: "/calculators/gst-calculator",
    component: GstCalculator,
    enabled: true,
  },
   {
    id: "Tax Calculator",
    path: "/calculators/tax-calculator",
    component: VatCalculator,
    enabled: true,
  },
 
  {
    id: "Discount Calculator",
    path: "/calculators/discount-calculator",
    component: DiscountCalculator,
    enabled:true, // 🚫 disabled without touching code
  },
   {
    id: "Incom Tax Calculator",
    path: "/calculators/income-tax-calculator",
    component: IncomeTaxCalculator,
    enabled:true, // 🚫 disabled without touching code
  },

   {
    id: "Pay-check Calculator",
    path: "/calculators/pay-check-calculator",
    component: PaycheckCalculator,
    enabled:true, // 🚫 disabled without touching code
  },
   
     {
    id: "Gratuity Calculator",
    path: "/calculators/gratuity-calculator",
    component: GratuityCalculator,
    enabled:true, // 🚫 disabled without touching code
  },
      {
    id: "NPS Calculator",
    path: "/calculators/nps-calculator",
    component: NpsCalculator,
    enabled:true, // 🚫 disabled without touching code
  },
       {
    id: "HRA Calculator",
    path: "/calculators/hra-calculator",
    component: HraCalculator,
    enabled:true, // 🚫 disabled without touching code
  },
        {
    id: "EPS Calculator",
    path: "/calculators/eps-calculator",
    component: EpsPensionCalculator,
    enabled:true, // 🚫 disabled without touching code
  },

      {
    id: "EMI Calculator",
    path: "/calculators/emi-calculator",
    component: EMICalculator,
    enabled:true, // 🚫 disabled without touching code
  },
];
