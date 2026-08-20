import { useQuery } from "@tanstack/react-query";
import { api } from "./client";

export function useDashboardStats() {
  return useQuery({
    queryKey: ["stats", "dashboard"],
    queryFn: async () => (await api.get("/api/stats/dashboard")).data,
    refetchInterval: 10000,
  });
}

export function useTimeline(hours = 24) {
  return useQuery({
    queryKey: ["stats", "timeline", hours],
    queryFn: async () => (await api.get("/api/stats/timeline", { params: { hours } })).data,
    refetchInterval: 30000,
  });
}

export function useTopAttackers(limit = 10) {
  return useQuery({
    queryKey: ["stats", "top-attackers", limit],
    queryFn: async () => (await api.get("/api/stats/top-attackers", { params: { limit } })).data,
    refetchInterval: 30000,
  });
}

export function useEvents(filters = {}) {
  return useQuery({
    queryKey: ["events", filters],
    queryFn: async () => (await api.get("/api/events", { params: filters })).data,
  });
}

export function useAlerts(filters = {}) {
  return useQuery({
    queryKey: ["alerts", filters],
    queryFn: async () => (await api.get("/api/alerts", { params: filters })).data,
    refetchInterval: 10000,
  });
}
