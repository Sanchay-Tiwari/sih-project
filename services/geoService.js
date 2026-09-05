const axios = require('axios');

/**
 * Origin IP Geolocation Service
 * Resolves physical coordinates, ISP, Autonomous System (AS), and Country/City.
 */
async function getGeoLocation(ipAddress) {
    const defaultData = {
        ip: ipAddress || 'Unknown',
        city: 'Unknown',
        region: 'Unknown',
        country: 'Unknown',
        countryCode: 'XX',
        lat: 0,
        lon: 0,
        isp: 'Unknown / Private Network',
        org: 'Unknown',
        as: 'Unknown'
    };

    if (!ipAddress || ipAddress === '127.0.0.1' || ipAddress.startsWith('10.') || ipAddress.startsWith('192.168.') || ipAddress.startsWith('172.16.')) {
        return {
            ...defaultData,
            city: 'Internal Network',
            country: 'Private Subnet',
            isp: 'Local / Private MTA Relay'
        };
    }

    // Primary Geo lookup via ip-api.com
    try {
        const response = await axios.get(`http://ip-api.com/json/${ipAddress}`, {
            timeout: 3500,
            params: {
                fields: 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query'
            }
        });

        const data = response.data;
        if (data && data.status === 'success' && data.lat && data.lon) {
            return {
                ip: ipAddress,
                city: data.city || 'Unknown',
                region: data.regionName || 'Unknown',
                country: data.country || 'Unknown',
                countryCode: data.countryCode || 'XX',
                lat: data.lat || 0,
                lon: data.lon || 0,
                isp: data.isp || 'Unknown',
                org: data.org || data.isp || 'Unknown',
                as: data.as || 'Unknown'
            };
        }
    } catch (error) {
        // Fall through to backup provider
    }

    // Secondary / Fallback Geo lookup via HTTPS ipwho.is
    try {
        const fallbackRes = await axios.get(`https://ipwho.is/${ipAddress}`, { timeout: 3500 });
        const fbData = fallbackRes.data;
        if (fbData && fbData.success) {
            return {
                ip: ipAddress,
                city: fbData.city || 'Unknown',
                region: fbData.region || 'Unknown',
                country: fbData.country || 'Unknown',
                countryCode: fbData.country_code || 'XX',
                lat: fbData.latitude || 0,
                lon: fbData.longitude || 0,
                isp: fbData.connection?.isp || 'Unknown',
                org: fbData.connection?.org || fbData.connection?.isp || 'Unknown',
                as: fbData.connection?.asn ? `AS${fbData.connection.asn} ${fbData.connection.org || ''}` : 'Unknown'
            };
        }
    } catch (fallbackErr) {
        console.warn(`GeoLocation secondary lookup failed for ${ipAddress}:`, fallbackErr.message);
    }

    return defaultData;
}

module.exports = { getGeoLocation };