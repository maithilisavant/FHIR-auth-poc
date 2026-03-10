import { Injectable } from '@nestjs/common';

@Injectable()
export class FhirApiService {
  getMockPatients(): object {
    return {
      resourceType: 'Bundle',
      type: 'searchset',
      total: 2,
      entry: [
        {
          resource: {
            resourceType: 'Patient',
            id: 'patient-001',
            name: [{ use: 'official', family: 'Smith', given: ['John'] }],
            birthDate: '1980-01-15',
            gender: 'male',
          },
        },
        {
          resource: {
            resourceType: 'Patient',
            id: 'patient-002',
            name: [{ use: 'official', family: 'Jones', given: ['Jane'] }],
            birthDate: '1992-06-30',
            gender: 'female',
          },
        },
      ],
    };
  }

  getCapabilityStatement(): object {
    return {
      resourceType: 'CapabilityStatement',
      status: 'active',
      date: new Date().toISOString().slice(0, 10),
      kind: 'instance',
      fhirVersion: '4.0.1',
      format: ['json'],
      rest: [
        {
          mode: 'server',
          security: {
            extension: [
              {
                url: 'http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris',
                extension: [
                  {
                    url: 'authorize',
                    valueUri: 'http://localhost:3000/auth/authorize',
                  },
                  {
                    url: 'token',
                    valueUri: 'http://localhost:3000/auth/token',
                  },
                  {
                    url: 'introspect',
                    valueUri: 'http://localhost:3000/auth/introspect',
                  },
                ],
              },
            ],
          },
          resource: [
            {
              type: 'Patient',
              interaction: [{ code: 'search-type' }, { code: 'read' }],
            },
          ],
        },
      ],
    };
  }
}