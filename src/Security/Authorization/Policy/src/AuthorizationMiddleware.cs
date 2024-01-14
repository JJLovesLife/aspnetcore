// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Authorization;

// This middleware exists to force the correct constructor overload to be called when the user calls UseAuthorization().
// Since we already expose the AuthorizationMiddleware type, we can't change the constructor signature without breaking it.
internal sealed class AuthorizationMiddlewareInternal(
    RequestDelegate next,
    IServiceProvider services,
    IAuthorizationPolicyProvider policyProvider,
    ILogger<AuthorizationMiddleware> logger) : AuthorizationMiddleware(next, policyProvider, services, logger)
{

}

/// <summary>
/// A middleware that enables authorization capabilities.
/// </summary>
public class AuthorizationMiddleware
{
    // AppContext switch used to control whether HttpContext or endpoint is passed as a resource to AuthZ
    private const string SuppressUseHttpContextAsAuthorizationResource = "Microsoft.AspNetCore.Authorization.SuppressUseHttpContextAsAuthorizationResource";

    // Property key is used by Endpoint routing to determine if Authorization has run
    private const string AuthorizationMiddlewareInvokedWithEndpointKey = "__AuthorizationMiddlewareWithEndpointInvoked";
    private static readonly object AuthorizationMiddlewareWithEndpointInvokedValue = new object();

    private readonly RequestDelegate _next;
    private readonly IAuthorizationPolicyProvider _policyProvider;
    private readonly bool _canCache;
    private readonly AuthorizationPolicyCache? _policyCache;
    private readonly ILogger<AuthorizationMiddleware>? _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="AuthorizationMiddleware"/>.
    /// </summary>
    /// <param name="next">The next middleware in the application middleware pipeline.</param>
    /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/>.</param>
    public AuthorizationMiddleware(RequestDelegate next,
        IAuthorizationPolicyProvider policyProvider)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _policyProvider = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
        _canCache = false;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="AuthorizationMiddleware"/>.
    /// </summary>
    /// <param name="next">The next middleware in the application middleware pipeline.</param>
    /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/>.</param>
    /// <param name="services">The <see cref="IServiceProvider"/>.</param>
    /// <param name="logger">The <see cref="ILogger"/>.</param>
    public AuthorizationMiddleware(RequestDelegate next,
        IAuthorizationPolicyProvider policyProvider,
        IServiceProvider services,
        ILogger<AuthorizationMiddleware> logger) : this(next, policyProvider, services)
    {
        _logger = logger;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="AuthorizationMiddleware"/>.
    /// </summary>
    /// <param name="next">The next middleware in the application middleware pipeline.</param>
    /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/>.</param>
    /// <param name="services">The <see cref="IServiceProvider"/>.</param>
    public AuthorizationMiddleware(RequestDelegate next,
        IAuthorizationPolicyProvider policyProvider,
        IServiceProvider services) : this(next, policyProvider)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (_policyProvider.AllowsCachingPolicies)
        {
            _policyCache = services.GetService<AuthorizationPolicyCache>();
            _canCache = _policyCache != null;
        }
    }

    /// <summary>
    /// Invokes the middleware performing authorization.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/>.</param>
    public async Task Invoke(HttpContext context)
    {
        /*
        依赖于endpoint机制
        */
        ArgumentNullException.ThrowIfNull(context);

        var endpoint = context.GetEndpoint();
        if (endpoint != null)
        {
            // EndpointRoutingMiddleware uses this flag to check if the Authorization middleware processed auth metadata on the endpoint.
            // The Authorization middleware can only make this claim if it observes an actual endpoint.
            context.Items[AuthorizationMiddlewareInvokedWithEndpointKey] = AuthorizationMiddlewareWithEndpointInvokedValue;
        }

        // Use the computed policy for this endpoint if we can
        AuthorizationPolicy? policy = null;
        var canCachePolicy = _canCache && endpoint != null;
        if (canCachePolicy)
        {
            policy = _policyCache!.Lookup(endpoint!);
        }

        if (policy == null)
        {
            // IMPORTANT: Changes to authorization logic should be mirrored in MVC's AuthorizeFilter
            // AuthorizeAttribute
            var authorizeData = endpoint?.Metadata.GetOrderedMetadata<IAuthorizeData>() ?? Array.Empty<IAuthorizeData>();

            var policies = endpoint?.Metadata.GetOrderedMetadata<AuthorizationPolicy>() ?? Array.Empty<AuthorizationPolicy>();

            // AuthorizationPolicyBuilder.Combine(provider.GetPolicy(data.Policy))
            //  .RequireRole(data.Roles.Split(','))
            //  .AuthenticationSchemes.Add(data.AuthenticationSchemes.Split(','))
            // two fallback 1. policyProvider.GetFallbackPolicyAsync() 2. policyProvider.GetDefaultPolicyAsync() based on different cases
            policy = await AuthorizationPolicy.CombineAsync(_policyProvider, authorizeData, policies);

            var requirementData = endpoint?.Metadata?.GetOrderedMetadata<IAuthorizationRequirementData>() ?? Array.Empty<IAuthorizationRequirementData>();
            if (requirementData.Count > 0)
            {
                var reqPolicy = new AuthorizationPolicyBuilder();
                foreach (var rd in requirementData)
                {
                    foreach (var r in rd.GetRequirements())
                    {
                        reqPolicy.AddRequirements(r);
                    }
                }

                // Combine policy with requirements or just use requirements if no policy
                policy = (policy is null)
                    ? reqPolicy.Build()
                    : AuthorizationPolicy.Combine(policy, reqPolicy.Build());
            }

            // Cache the computed policy
            if (policy != null && canCachePolicy)
            {
                _policyCache!.Store(endpoint!, policy);
            }
        }

        // A policy is just a list of schemes + a list of requirement
        if (policy == null)
        {
            await _next(context);
            return;
        }

        // Policy evaluator has transient lifetime so it's fetched from request services instead of injecting in constructor
        var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();

        // 如果没有scheme，用HttpContext已有的。否则context.AuthenticateAsync(scheme)然后merge所有的scheme
        // Q: 如果之前的Authentication已经验证过了，但是这个有指定了相同scheme，这里会重复验证吗？
        var authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);
        if (authenticateResult?.Succeeded ?? false)
        {
            if (context.Features.Get<IAuthenticateResultFeature>() is IAuthenticateResultFeature authenticateResultFeature)
            {
                authenticateResultFeature.AuthenticateResult = authenticateResult;
            }
            else
            {
                var authFeatures = new AuthenticationFeatures(authenticateResult);
                context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
                context.Features.Set<IAuthenticateResultFeature>(authFeatures);
            }
        }

        // Allow Anonymous still wants to run authorization to populate the User but skips any failure/challenge handling
        if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() != null)
        {
            await _next(context);
            return;
        }

        if (authenticateResult != null && !authenticateResult.Succeeded && _logger is ILogger log && log.IsEnabled(LogLevel.Debug))
        {
            log.LogDebug("Policy authentication schemes {policyName} did not succeed", String.Join(", ", policy.AuthenticationSchemes));
        }

        object? resource;
        if (AppContext.TryGetSwitch(SuppressUseHttpContextAsAuthorizationResource, out var useEndpointAsResource) && useEndpointAsResource)
        {
            resource = endpoint;
        }
        else
        {
            resource = context;
        }

        // IAuthorizationService.AuthorizeAsync, 基本上就是调用所有IAuthorizationHandler.HandleAsync
        var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult!, context, resource);
        var authorizationMiddlewareResultHandler = context.RequestServices.GetRequiredService<IAuthorizationMiddlewareResultHandler>();
        // default: 成功next，Challenged则ChallengeAsync(AuthN失败)，forbidden则ForbidAsync(AuthN成功，但是AuthZ失败)
        await authorizationMiddlewareResultHandler.HandleAsync(_next, context, policy, authorizeResult);
    }

}
