import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
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

export function useEvents(filters = {}, refetchInterval = false) {
  return useQuery({
    queryKey: ["events", filters],
    queryFn: async () => (await api.get("/api/events", { params: filters })).data,
    refetchInterval,
  });
}

export function useAlerts(filters = {}) {
  return useQuery({
    queryKey: ["alerts", filters],
    queryFn: async () => (await api.get("/api/alerts", { params: filters })).data,
    refetchInterval: 10000,
  });
}

export function useIncidents(filters = {}) {
  return useQuery({
    queryKey: ["incidents", filters],
    queryFn: async () => (await api.get("/api/incidents", { params: filters })).data,
    refetchInterval: 15000,
  });
}

export function useIncident(id) {
  return useQuery({
    queryKey: ["incidents", id],
    queryFn: async () => (await api.get(`/api/incidents/${id}`)).data,
    enabled: id != null,
  });
}

export function useRules() {
  return useQuery({
    queryKey: ["rules"],
    queryFn: async () => (await api.get("/api/rules")).data,
  });
}

export function useToggleRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ruleId) => (await api.post(`/api/rules/${ruleId}/toggle`)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });
}

export function useUpdateRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ ruleId, body }) => (await api.put(`/api/rules/${ruleId}`, body)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });
}

export function useEnrichIp() {
  return useMutation({
    mutationFn: async (ip) => (await api.get(`/api/enrich/ip/${ip}`)).data,
  });
}

export function useAdminUsers() {
  return useQuery({
    queryKey: ["admin", "users"],
    queryFn: async () => (await api.get("/api/admin/users")).data,
  });
}

export function useCreateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body) => (await api.post("/api/admin/users", body)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin", "users"] }),
  });
}

export function useUpdateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, body }) => (await api.put(`/api/admin/users/${userId}`, body)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin", "users"] }),
  });
}

export function useSuspendUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (userId) => (await api.post(`/api/admin/users/${userId}/suspend`)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin", "users"] }),
  });
}

export function useAuditLog(filters = {}) {
  return useQuery({
    queryKey: ["admin", "audit", filters],
    queryFn: async () => (await api.get("/api/admin/audit", { params: filters })).data,
  });
}

export function useSetupValidate() {
  return useQuery({
    queryKey: ["setup", "validate"],
    queryFn: async () => (await api.get("/api/setup/validate")).data,
  });
}
