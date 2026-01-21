import React, { useState } from 'react';
import { Routes, Route } from 'react-router-dom';

import LandingPage from './components/LandingPage';
import ProductDetailsPage from './components/ProductDetailsPage';
import DetailedSidebar from './components/DetailedSidebar';
import LoginPage from './components/LoginPage';
import DashboardHeader from './components/DashboardHeader';
import DashboardWidgets from './components/DashboardWidgets';

import { domains } from './data/domains';
import { Domain } from './types/Domain';
import { User } from './types/User';
import { SubscriptionPlan, UserSubscription } from './types/Subscription';
import { CalculatorRoutes } from './components/calculator-module';



function App() {
  const [selectedDomain, setSelectedDomain] = useState<Domain | null>(null);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [showProductDetails, setShowProductDetails] = useState<Domain | null>(null);
  const [userSubscriptions, setUserSubscriptions] = useState<UserSubscription[]>([]);

  const handleDomainSelect = (domain: Domain) => {
    setSelectedDomain(domain);
    setShowProductDetails(null);
  };

  const handleExploreProduct = (domain: Domain) => {
    setShowProductDetails(domain);
  };

  const handleBackToHome = () => {
    setSelectedDomain(null);
    setShowLogin(false);
    setShowProductDetails(null);
  };

  const handleShowLogin = () => {
    setShowLogin(true);
    setShowProductDetails(null);
  };

  const handleLogin = (user: User) => {
    setCurrentUser(user);
    setShowLogin(false);

    // Auto-select first assigned domain
    const firstDomain = domains.find(d => user.assignedDomains.includes(d.id));
    if (firstDomain) {
      setSelectedDomain(firstDomain);
    }
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setSelectedDomain(null);
    setShowLogin(false);
    setShowProductDetails(null);
  };

  const handleGetStartedFromProduct = (domain: Domain, selectedPlan?: SubscriptionPlan) => {
    if (selectedPlan) {
      const newSubscription: UserSubscription = {
        domainId: domain.id,
        planId: selectedPlan.id,
        status: 'trial',
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      };
      setUserSubscriptions(prev => [...prev, newSubscription]);
    }
    setShowProductDetails(null);
    setShowLogin(true);
  };

  return (
    <Routes>
     
            {/* ✅ Calculator Module (ISOLATED) */}
      <Route path="/calculators/*" element={<CalculatorRoutes />} />

      {/* ❗ Existing App (UNCHANGED) */}
      <Route
        path="*"
        element={
          showProductDetails ? (
            <ProductDetailsPage
              domain={showProductDetails}
              onBackToHome={handleBackToHome}
              onGetStarted={handleGetStartedFromProduct}
            />
          ) : showLogin && !currentUser ? (
            <LoginPage onLogin={handleLogin} onBackToHome={handleBackToHome} />
          ) : !currentUser || !selectedDomain ? (
            <LandingPage
              onDomainSelect={handleDomainSelect}
              onShowLogin={handleShowLogin}
              onExploreProduct={handleExploreProduct}
            />
          ) : (
            <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 flex">
              <DetailedSidebar
                domains={domains}
                selectedDomain={selectedDomain}
                user={currentUser}
                onDomainSelect={handleDomainSelect}
                onBackToHome={handleBackToHome}
                onLogout={handleLogout}
              />
              <div className="flex-1 flex flex-col">
                <DashboardHeader selectedDomain={selectedDomain} />
                <main className="flex-1 overflow-auto">
                  <DashboardWidgets selectedDomain={selectedDomain} />
                </main>
              </div>
            </div>
          )
        }
      />
    </Routes>
  );
}

export default App;
