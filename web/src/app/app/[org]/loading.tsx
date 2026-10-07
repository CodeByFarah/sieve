import { Skeleton } from "@/components/ui";

export default function Loading() {
  return (
    <div className="space-y-6" aria-busy="true" aria-label="Loading">
      <Skeleton className="h-8 w-80" />
      <Skeleton className="h-3 w-full" />
      <div className="grid grid-cols-4 gap-6">
        {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-14" />)}
      </div>
      <Skeleton className="h-64 w-full" />
    </div>
  );
}
