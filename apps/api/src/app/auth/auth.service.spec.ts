import { ConfigurationService } from '@ghostfolio/api/services/configuration/configuration.service';
import { PropertyService } from '@ghostfolio/api/services/property/property.service';

import { InternalServerErrorException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { UserService } from '../user/user.service';
import { AuthService } from './auth.service';

describe('AuthService', () => {
  let authService: AuthService;
  let configurationService: jest.Mocked<ConfigurationService>;
  let jwtService: jest.Mocked<JwtService>;
  let propertyService: jest.Mocked<PropertyService>;
  let userService: jest.Mocked<UserService>;

  beforeEach(() => {
    configurationService = {
      get: jest.fn()
    } as unknown as jest.Mocked<ConfigurationService>;

    jwtService = {
      sign: jest.fn().mockReturnValue('signed-token')
    } as unknown as jest.Mocked<JwtService>;

    propertyService = {
      isUserSignupEnabled: jest.fn()
    } as unknown as jest.Mocked<PropertyService>;

    userService = {
      createAccessToken: jest.fn(),
      createUser: jest.fn(),
      users: jest.fn()
    } as unknown as jest.Mocked<UserService>;

    authService = new AuthService(
      configurationService,
      jwtService,
      propertyService,
      userService
    );
  });

  describe('validateAnonymousLogin', () => {
    it('returns authToken for existing user', async () => {
      userService.createAccessToken.mockReturnValue('hashed-token');
      userService.users.mockResolvedValue([{ id: 'user-1' }] as any);

      const token = await authService.validateAnonymousLogin('raw-token');

      expect(token).toBe('signed-token');
      expect(jwtService.sign).toHaveBeenCalledWith({ id: 'user-1' });
    });

    it('throws when no user found', async () => {
      userService.createAccessToken.mockReturnValue('hashed-token');
      userService.users.mockResolvedValue([]);

      await expect(
        authService.validateAnonymousLogin('bad-token')
      ).rejects.toThrow();
    });
  });

  describe('validateOAuthLogin', () => {
    const params = { provider: 'GOOGLE' as any, thirdPartyId: 'gid-123' };

    it('returns authToken for existing OAuth user', async () => {
      userService.users.mockResolvedValue([{ id: 'user-oauth' }] as any);

      const token = await authService.validateOAuthLogin(params);

      expect(token).toBe('signed-token');
      expect(userService.createUser).not.toHaveBeenCalled();
    });

    describe('when user does not exist', () => {
      beforeEach(() => {
        userService.users.mockResolvedValue([]);
      });

      it('throws when DISALLOW_REGISTRATION=true', async () => {
        configurationService.get.mockReturnValue(true);

        await expect(authService.validateOAuthLogin(params)).rejects.toThrow(
          InternalServerErrorException
        );
        expect(userService.createUser).not.toHaveBeenCalled();
      });

      it('throws when signup disabled via property', async () => {
        configurationService.get.mockReturnValue(false);
        propertyService.isUserSignupEnabled.mockResolvedValue(false);

        await expect(authService.validateOAuthLogin(params)).rejects.toThrow(
          InternalServerErrorException
        );
        expect(userService.createUser).not.toHaveBeenCalled();
      });

      it('creates user and returns token when registration allowed', async () => {
        configurationService.get.mockReturnValue(false);
        propertyService.isUserSignupEnabled.mockResolvedValue(true);
        userService.createUser.mockResolvedValue({ id: 'new-user' } as any);

        const token = await authService.validateOAuthLogin(params);

        expect(token).toBe('signed-token');
        expect(userService.createUser).toHaveBeenCalledWith({
          data: { provider: 'GOOGLE', thirdPartyId: 'gid-123' }
        });
      });

      it('does not check property service when DISALLOW_REGISTRATION=true', async () => {
        configurationService.get.mockReturnValue(true);

        await expect(authService.validateOAuthLogin(params)).rejects.toThrow();
        expect(propertyService.isUserSignupEnabled).not.toHaveBeenCalled();
      });
    });
  });
});
