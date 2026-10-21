"use client";

type Props = { body: string; author: string };

export function Comment({ body, author }: Props) {
  return (
    <div className="comment">
      <strong>{author}</strong>
      <div dangerouslySetInnerHTML={{ __html: body }} />
    </div>
  );
}
