export const mutation = `mutation UpdateEmail($email: String!) { updateEmail(email: $email) { ok } }`;
export function render(el, html) { el.insertAdjacentHTML("beforeend", html); }
