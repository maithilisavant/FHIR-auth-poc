export class TokenRequestDto {
  grant_type: string;
  code?: string;
  redirect_uri?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
  refresh_token?: string;
  assertion?: string;
}