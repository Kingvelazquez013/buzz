import * as React from "react";

import { useKeepMentionedAgentsPinned } from "@/features/messages/lib/autoPinMentionedAgentsPreference";
import { usePersistentAgentAudience } from "@/features/messages/lib/persistentAgentAudience";

export function useThreadAgentAudience({
  isAgentPubkey,
  rootTags,
  scope,
}: {
  isAgentPubkey: (pubkey: string) => boolean;
  rootTags: readonly string[][];
  scope: string | null;
}) {
  const audience = usePersistentAgentAudience(scope);
  const keepMentionedAgentsPinned = useKeepMentionedAgentsPinned();

  React.useEffect(() => {
    if (!scope || !keepMentionedAgentsPinned) return;
    for (const tag of rootTags) {
      const pubkey = tag[0] === "p" ? tag[1] : null;
      if (pubkey && isAgentPubkey(pubkey)) audience.addPubkey(pubkey);
    }
  }, [
    audience.addPubkey,
    isAgentPubkey,
    keepMentionedAgentsPinned,
    rootTags,
    scope,
  ]);

  return { audience, keepMentionedAgentsPinned };
}
