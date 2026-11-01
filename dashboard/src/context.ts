import { createContext, useContext } from "react";
import type { Api } from "./api";

export const ApiContext = createContext<Api | null>(null);

export function useApi(): Api {
  const api = useContext(ApiContext);
  if (api === null) throw new Error("useApi needs a signed-in session");
  return api;
}
