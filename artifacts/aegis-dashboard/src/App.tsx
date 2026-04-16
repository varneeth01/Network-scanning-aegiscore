import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Analyze from "./pages/Analyze";
import Sandbox from "./pages/Sandbox";
import Training from "./pages/Training";
import ConfusionMatrix from "./pages/ConfusionMatrix";
import FeatureImportance from "./pages/FeatureImportance";
import Shap from "./pages/Shap";
import Performance from "./pages/Performance";
import AIChat from "./pages/AIChat";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30000,
    },
  },
});

function Router() {
  return (
    <Layout>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route path="/analyze" component={Analyze} />
        <Route path="/sandbox" component={Sandbox} />
        <Route path="/training" component={Training} />
        <Route path="/confusion" component={ConfusionMatrix} />
        <Route path="/features" component={FeatureImportance} />
        <Route path="/shap" component={Shap} />
        <Route path="/performance" component={Performance} />
        <Route path="/ai" component={AIChat} />
        <Route>
          <div className="flex items-center justify-center h-96">
            <div className="text-center">
              <div className="text-4xl font-bold text-muted-foreground">404</div>
              <div className="text-sm text-muted-foreground mt-2">Page not found</div>
            </div>
          </div>
        </Route>
      </Switch>
    </Layout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
