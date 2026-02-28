import { createBrowserRouter } from "react-router";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { Configuration } from "./pages/Configuration";
import { Processes } from "./pages/Processes";
import { Layout } from "./components/Layout";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: Dashboard },
      { path: "events", Component: Events },
      { path: "configuration", Component: Configuration },
      { path: "processes", Component: Processes },
    ],
  },
]);
