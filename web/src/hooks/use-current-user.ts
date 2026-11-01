"use client";

import { auth, type CurrentUser } from "@/lib/auth";

export function useCurrentUser(): CurrentUser {
  return auth.getCurrentUser();
}
