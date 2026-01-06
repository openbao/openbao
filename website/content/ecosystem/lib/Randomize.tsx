import shuffle from "lodash/shuffle";

export default function Randomize({children}) {
  return shuffle(children);
}
