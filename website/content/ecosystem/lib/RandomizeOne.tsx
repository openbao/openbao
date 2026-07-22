import shuffle from "lodash/shuffle";
import { Children } from "react";

export default function RandomizeOne({children}) {
  const items = Children.toArray(children);
  return shuffle(items)[0];
}
