import React from "react";
import { ArrowRight, BarChart3, Calculator, Users, Zap } from "lucide-react";
import DomainCard from "./DomainCard";
import { domains } from "../data/domains";
import { Domain } from "../types/Domain";
import { useNavigate } from "react-router-dom";

interface LandingPageProps {
  onDomainSelect: (domain: Domain) => void;
  onShowLogin: () => void;
  onExploreProduct: (domain: Domain) => void;
}

const LandingPage: React.FC<LandingPageProps> = ({
  onDomainSelect,
  onShowLogin,
  onExploreProduct,
}) => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 relative overflow-hidden">
      {/* Background Elements */}
      <div className="absolute top-0 left-0 w-full h-full overflow-hidden">
        <div className="absolute -top-40 -right-40 w-96 h-96 bg-gradient-to-br from-blue-400/30 via-purple-400/20 to-pink-400/30 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-gradient-to-tr from-green-400/20 via-blue-400/30 to-purple-400/20 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-64 h-64 bg-gradient-to-r from-yellow-400/10 via-red-400/10 to-pink-400/10 rounded-full blur-2xl animate-pulse delay-500"></div>
      </div>

      {/* Header */}
      <header className="relative z-10 backdrop-blur-sm bg-white/70 border-b border-white/20 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-12 h-12 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-xl flex items-center justify-center shadow-lg">
                <Zap className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-700 bg-clip-text text-transparent">
                  OPTIM OPS
                </h1>
                <p className="text-sm text-gray-600 font-medium">
                  One Platform. Infinite Possibilities.
                </p>
              </div>
            </div>
            <div className="flex justify-end items-center gap-4">
              <button
                onClick={() => navigate("/calculators")}
                className="px-7 py-3 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 
               text-white border border-blue-600 rounded-2xl font-semibold 
               shadow-md hover:shadow-lg transform hover:scale-105 
               transition-all duration-300  flex items-center gap-2"
              >
                <Calculator className="w-6 h-6 text-white" />
                <span>Calculators</span>
              </button>

              <button
                onClick={onShowLogin}
                className="px-8 py-3 bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-700 
               hover:from-blue-700 hover:via-purple-700 hover:to-indigo-800 
               text-white rounded-2xl font-semibold shadow-lg hover:shadow-xl 
               transform hover:scale-105 transition-all duration-300 
               flex items-center  space-x-2"
              >
                <span>Get Started</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative z-10 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <div className="max-w-4xl mx-auto">
            <h2 className="text-6xl font-bold bg-gradient-to-r from-gray-900 via-blue-800 to-purple-800 bg-clip-text text-transparent leading-tight mb-8">
              Transform Your Operations
              <span className="block text-5xl bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-700 bg-clip-text text-transparent">
                Across Every Industry
              </span>
            </h2>
            <p className="text-xl text-gray-600 mb-12 max-w-3xl mx-auto leading-relaxed">
              Experience the power of unified operations management with our
              comprehensive platform designed for healthcare, finance, beauty,
              food service, manufacturing, and retail industries.
            </p>

            {/* Dashboard Preview */}
            <div className="relative max-w-4xl mx-auto mb-16">
              <div className="relative bg-gradient-to-br from-white/90 via-white/70 to-white/50 backdrop-blur-xl rounded-3xl shadow-2xl border border-white/20 overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-blue-500/10 via-purple-500/10 to-indigo-500/10"></div>
                <div className="relative p-8">
                  <div className="flex items-center space-x-4 mb-6">
                    <div className="flex space-x-2">
                      <div className="w-3 h-3 bg-gradient-to-r from-red-400 to-red-500 rounded-full"></div>
                      <div className="w-3 h-3 bg-gradient-to-r from-yellow-400 to-yellow-500 rounded-full"></div>
                      <div className="w-3 h-3 bg-gradient-to-r from-green-400 to-green-500 rounded-full"></div>
                    </div>
                    <div className="flex-1 h-8 bg-gradient-to-r from-gray-200/50 to-gray-300/50 rounded-xl"></div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-gradient-to-br from-blue-50/80 to-blue-100/60 backdrop-blur-sm rounded-2xl p-6 border border-blue-200/30">
                      <div className="flex items-center space-x-3 mb-4">
                        <BarChart3 className="w-6 h-6 text-blue-600" />
                        <span className="font-semibold text-blue-900">
                          Analytics
                        </span>
                      </div>
                      <div className="space-y-2">
                        <div className="h-2 bg-gradient-to-r from-blue-300 to-blue-500 rounded-full"></div>
                        <div className="h-2 bg-gradient-to-r from-blue-200 to-blue-400 rounded-full w-3/4"></div>
                        <div className="h-2 bg-gradient-to-r from-blue-100 to-blue-300 rounded-full w-1/2"></div>
                      </div>
                    </div>
                    <div className="bg-gradient-to-br from-green-50/80 to-green-100/60 backdrop-blur-sm rounded-2xl p-6 border border-green-200/30">
                      <div className="flex items-center space-x-3 mb-4">
                        <Users className="w-6 h-6 text-green-600" />
                        <span className="font-semibold text-green-900">
                          Management
                        </span>
                      </div>
                      <div className="space-y-2">
                        <div className="h-2 bg-gradient-to-r from-green-300 to-green-500 rounded-full w-4/5"></div>
                        <div className="h-2 bg-gradient-to-r from-green-200 to-green-400 rounded-full w-3/5"></div>
                        <div className="h-2 bg-gradient-to-r from-green-100 to-green-300 rounded-full w-2/3"></div>
                      </div>
                    </div>
                    <div className="bg-gradient-to-br from-purple-50/80 to-purple-100/60 backdrop-blur-sm rounded-2xl p-6 border border-purple-200/30">
                      <div className="flex items-center space-x-3 mb-4">
                        <Zap className="w-6 h-6 text-purple-600" />
                        <span className="font-semibold text-purple-900">
                          Automation
                        </span>
                      </div>
                      <div className="space-y-2">
                        <div className="h-2 bg-gradient-to-r from-purple-300 to-purple-500 rounded-full w-5/6"></div>
                        <div className="h-2 bg-gradient-to-r from-purple-200 to-purple-400 rounded-full w-2/3"></div>
                        <div className="h-2 bg-gradient-to-r from-purple-100 to-purple-300 rounded-full w-3/4"></div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Domains Grid */}
      <section className="relative z-10 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h3 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-blue-800 to-purple-800 bg-clip-text text-transparent mb-4">
              Choose Your Industry
            </h3>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Select from our specialized solutions designed for your specific
              business needs
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {domains.map((domain) => (
              <DomainCard
                key={domain.id}
                domain={domain}
                onClick={() => onDomainSelect(domain)}
                onExplore={() => onExploreProduct(domain)}
              />
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 bg-gradient-to-r from-gray-900 via-blue-900 to-purple-900 text-white py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div className="col-span-1 md:col-span-2">
              <div className="flex items-center space-x-3 mb-4">
                <div className="w-10 h-10 bg-gradient-to-br from-blue-400 via-purple-400 to-indigo-500 rounded-xl flex items-center justify-center">
                  <Zap className="w-5 h-5 text-white" />
                </div>
                <span className="text-2xl font-bold">OPTIM OPS</span>
              </div>
              <p className="text-gray-300 mb-6 max-w-md">
                Empowering businesses across industries with comprehensive
                operations management solutions.
              </p>
              <button
                onClick={onShowLogin}
                className="px-8 py-3 bg-gradient-to-r from-blue-500 via-purple-500 to-indigo-600 hover:from-blue-600 hover:via-purple-600 hover:to-indigo-700 text-white rounded-2xl font-semibold shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300"
              >
                Get Started with OPTIM OPS
              </button>
            </div>

            <div>
              <h4 className="text-lg font-semibold mb-4">Quick Links</h4>
              <ul className="space-y-2 text-gray-300">
                <li>
                  <a
                    href="#"
                    className="hover:text-white transition-colors duration-200"
                  >
                    About
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="hover:text-white transition-colors duration-200"
                  >
                    Features
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="hover:text-white transition-colors duration-200"
                  >
                    Pricing
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="hover:text-white transition-colors duration-200"
                  >
                    Industries
                  </a>
                </li>
              </ul>
            </div>

            <div>
              <h4 className="text-lg font-semibold mb-4">Support</h4>
              <ul className="space-y-2 text-gray-300">
                <li>
                  <a
                    href="#"
                    className="hover:text-white transition-colors duration-200"
                  >
                    Contact
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="hover:text-white transition-colors duration-200"
                  >
                    Help Center
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="hover:text-white transition-colors duration-200"
                  >
                    Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="hover:text-white transition-colors duration-200"
                  >
                    Community
                  </a>
                </li>
              </ul>
            </div>
          </div>

          <div className="border-t border-gray-700 mt-12 pt-8 text-center text-gray-400">
            <p>&copy; 2025 OPTIM OPS. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
