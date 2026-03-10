export class AuthorizeDto {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  launch?: string;
  iss?: string;
}