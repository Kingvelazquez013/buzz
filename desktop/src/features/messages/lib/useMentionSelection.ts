import * as React from "react";
import type { MentionSuggestion } from "@/features/messages/ui/MentionAutocomplete";

export type MentionPickerMode = "first-agent" | "preserve" | null;
const keyOf = (s: MentionSuggestion) =>
  s.pubkey ?? s.personaId ?? s.teamId ?? s.displayName;

/** Keyboard intent follows an exact identity, not an asynchronously sorted index. */
export function useMentionSelection(suggestions: MentionSuggestion[]) {
  const [selection, setSelection] = React.useState<{
    key: string | null;
    index: number;
    deliberate: boolean;
  }>({ key: null, index: 0, deliberate: false });
  const preferAgentSelectionRef = React.useRef(false);
  const mentionSelectedIndex =
    selection.key === null
      ? Math.min(selection.index, Math.max(0, suggestions.length - 1))
      : suggestions.findIndex((s) => keyOf(s) === selection.key);
  const currentRef = React.useRef({ suggestions, mentionSelectedIndex });
  currentRef.current = { suggestions, mentionSelectedIndex };
  const setMentionSelectedIndex = React.useCallback(
    (value: React.SetStateAction<number>) => {
      const { suggestions: rows, mentionSelectedIndex: current } =
        currentRef.current;
      const deliberate = typeof value === "function";
      const index = deliberate ? value(current) : value;
      setSelection({
        key: deliberate && rows[index] ? keyOf(rows[index]) : null,
        index,
        deliberate,
      });
    },
    [],
  );
  React.useEffect(() => {
    if (!preferAgentSelectionRef.current || suggestions.length === 0) return;
    preferAgentSelectionRef.current = false;
    const index = suggestions.findIndex((s) => s.isAgent && s.pubkey);
    if (index >= 0)
      setSelection({
        key: keyOf(suggestions[index]),
        index,
        deliberate: false,
      });
  }, [suggestions]);
  const clearAgentSelectionPreference = React.useCallback(() => {
    preferAgentSelectionRef.current = false;
    setSelection({ key: null, index: 0, deliberate: false });
  }, []);
  const prepareSelectionPreference = React.useCallback(
    (preference: MentionPickerMode) => {
      preferAgentSelectionRef.current = preference === "first-agent";
    },
    [],
  );
  return {
    clearAgentSelectionPreference,
    mentionSelectedIndex,
    hasDeliberateSelection: selection.deliberate,
    prepareSelectionPreference,
    setMentionSelectedIndex,
  };
}
